/*!
 *  @file ColorBleedSandbox.h
 *  @brief Fork-based process isolation for unsafe ICC profile operations
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 1.0.0
 *
 *  Each profile operation runs in a forked child process with resource
 *  limits (memory, CPU, file size). If the unpatched iccDEV library
 *  crashes (SIGSEGV, SIGABRT, etc.), the parent process catches the
 *  signal and reports it as a security finding — the tool itself
 *  never crashes.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_SANDBOX_H
#define COLORBLEED_SANDBOX_H

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <functional>

struct SandboxResult {
    int  exit_code;    // Child exit code (0 = success)
    int  signal_num;   // Signal that killed child (0 = none)
    bool timed_out;    // SIGXCPU / RLIMIT_CPU exceeded
    bool oom_killed;   // RLIMIT_AS exceeded or SIGKILL from OOM
    bool crashed;      // Any abnormal termination

    const char* SignalName() const {
        if (!signal_num) return "none";
        switch (signal_num) {
            case SIGSEGV: return "SIGSEGV (segmentation fault)";
            case SIGABRT: return "SIGABRT (abort)";
            case SIGBUS:  return "SIGBUS (bus error)";
            case SIGFPE:  return "SIGFPE (floating point exception)";
            case SIGILL:  return "SIGILL (illegal instruction)";
            case SIGXCPU: return "SIGXCPU (CPU time limit)";
            case SIGXFSZ: return "SIGXFSZ (file size limit)";
            case SIGKILL: return "SIGKILL (killed — likely OOM)";
            default:      return strsignal(signal_num);
        }
    }

    void Report(const char* operation, const char* filename) const {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  ColorBleed Sandbox Report                          ║\n");
        fprintf(stderr, "╠══════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Operation: %-40s ║\n", operation);
        fprintf(stderr, "║  File:      %-40s ║\n", filename);

        if (!crashed) {
            fprintf(stderr, "║  Status:    CLEAN EXIT (code %d)%-21s║\n",
                    exit_code, "");
        } else if (signal_num) {
            fprintf(stderr, "║  Status:    *** CRASH DETECTED ***%-18s║\n", "");
            fprintf(stderr, "║  Signal:    %-40s ║\n", SignalName());
            if (timed_out)
                fprintf(stderr, "║  Detail:    CPU time limit exceeded%-17s║\n", "");
            if (oom_killed)
                fprintf(stderr, "║  Detail:    Memory limit exceeded%-19s║\n", "");
        } else {
            fprintf(stderr, "║  Status:    ABNORMAL EXIT (code %d)%-18s║\n",
                    exit_code, "");
        }

        fprintf(stderr, "╚══════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
    }
};

struct SandboxLimits {
    size_t max_mem_mb   = 4096;  // RLIMIT_AS  — virtual memory cap
    size_t max_cpu_sec  = 120;   // RLIMIT_CPU — CPU time cap
    size_t max_fsize_mb = 512;   // RLIMIT_FSIZE — output file size cap
};

/// Apply resource limits in the child process
static void ApplyChildLimits(const SandboxLimits& limits) {
    struct rlimit rl;

    // Virtual memory — skip when ASan is active (ASan reserves ~20TB shadow)
#if !defined(__SANITIZE_ADDRESS__) && !__has_feature(address_sanitizer)
    rl.rlim_cur = rl.rlim_max = limits.max_mem_mb * 1024ULL * 1024ULL;
    setrlimit(RLIMIT_AS, &rl);
#else
    (void)limits.max_mem_mb; // ASan provides its own rss_limit_mb
#endif

    // CPU time
    rl.rlim_cur = rl.rlim_max = limits.max_cpu_sec;
    setrlimit(RLIMIT_CPU, &rl);

    // Output file size
    rl.rlim_cur = rl.rlim_max = limits.max_fsize_mb * 1024ULL * 1024ULL;
    setrlimit(RLIMIT_FSIZE, &rl);

    // Core dump size — disable (we capture the signal instead)
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

/// Run a function in a forked child process with resource limits.
/// Returns SandboxResult describing how the child exited.
static SandboxResult RunSandboxed(std::function<int()> fn,
                                   const SandboxLimits& limits = {}) {
    SandboxResult result = {};

    // Flush before fork to prevent double-output
    fflush(stdout);
    fflush(stderr);

    pid_t child = fork();

    if (child < 0) {
        fprintf(stderr, "[ColorBleed] FATAL: fork() failed: %s\n", strerror(errno));
        result.exit_code = -1;
        result.crashed = true;
        return result;
    }

    if (child == 0) {
        // === CHILD PROCESS ===
        ApplyChildLimits(limits);

        // Reset signal handlers to default (ASan installs its own)
        // so that crashes propagate normally to waitpid()
        signal(SIGSEGV, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
        signal(SIGBUS,  SIG_DFL);
        signal(SIGFPE,  SIG_DFL);

        int rc = fn();
        _exit(rc);
    }

    // === PARENT PROCESS ===
    int status = 0;
    pid_t waited = waitpid(child, &status, 0);

    if (waited < 0) {
        fprintf(stderr, "[ColorBleed] FATAL: waitpid() failed: %s\n", strerror(errno));
        result.exit_code = -1;
        result.crashed = true;
        return result;
    }

    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
        result.crashed = (result.exit_code != 0);
    } else if (WIFSIGNALED(status)) {
        result.signal_num = WTERMSIG(status);
        result.crashed = true;

        if (result.signal_num == SIGXCPU)
            result.timed_out = true;
        if (result.signal_num == SIGKILL)
            result.oom_killed = true;
    }

    return result;
}

#endif // COLORBLEED_SANDBOX_H
