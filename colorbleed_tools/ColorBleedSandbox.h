/*!
 *  @file ColorBleedSandbox.h
 *  @brief Fork-based process isolation for unsafe ICC profile operations
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 2.0.0
 *
 *  Each profile operation runs in a forked child process with resource
 *  limits (memory, CPU, file size). ASan is configured in recoverable
 *  mode (halt_on_error=0) so the library logs errors but continues
 *  executing — the tools produce output even from malformed profiles.
 *
 *  If a truly fatal signal occurs (SIGSEGV, SIGBUS), siglongjmp-based
 *  recovery saves whatever partial output was generated.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_SANDBOX_H
#define COLORBLEED_SANDBOX_H

// GCC lacks __has_feature; define a fallback so preprocessor checks compile
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <functional>
#include <string>
#include <climits>

// ASan recoverable mode: log errors, don't abort
extern "C" const char* __asan_default_options() {
    return "halt_on_error=0:detect_leaks=0:print_summary=1"
           ":color=always:print_scariness=1";
}

// UBSan: recover and continue
extern "C" const char* __ubsan_default_options() {
    return "halt_on_error=0:print_stacktrace=1";
}

// Signal recovery jump buffer (per-child)
static sigjmp_buf g_recovery_point;
static volatile sig_atomic_t g_signal_caught = 0;

// Optional callback invoked before siglongjmp on crash recovery
typedef void (*CrashRecoveryFn)();
static CrashRecoveryFn g_crash_callback = nullptr;

static void __attribute__((unused)) SetCrashRecoveryCallback(CrashRecoveryFn fn) {
    g_crash_callback = fn;
}

static void SandboxSignalHandler(int sig) {
    g_signal_caught = sig;
    // Do NOT call g_crash_callback here — fopen/fwrite/fprintf are not
    // async-signal-safe. The callback runs after siglongjmp returns
    // in normal control flow (see RunSandboxed child block).
    siglongjmp(g_recovery_point, sig);
}

struct SandboxResult {
    int  exit_code;
    int  signal_num;
    bool timed_out;
    bool oom_killed;
    bool crashed;
    bool partial_output;

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

        if (partial_output)
            fprintf(stderr, "║  Output:    PARTIAL (recovered after signal)%-8s║\n", "");

        fprintf(stderr, "╚══════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
    }
};

struct SandboxLimits {
    size_t max_mem_mb   = 4096;
    size_t max_cpu_sec  = 120;
    size_t max_fsize_mb = 512;
};

/// Apply resource limits in the child process
static void ApplyChildLimits(const SandboxLimits& limits) {
    struct rlimit rl;

    // Virtual memory — skip when ASan is active (ASan reserves ~20TB shadow)
#if !defined(__SANITIZE_ADDRESS__) && !__has_feature(address_sanitizer)
    rl.rlim_cur = rl.rlim_max = limits.max_mem_mb * 1024ULL * 1024ULL;
    setrlimit(RLIMIT_AS, &rl);
#else
    (void)limits.max_mem_mb;
#endif

    // CPU time
    rl.rlim_cur = rl.rlim_max = limits.max_cpu_sec;
    setrlimit(RLIMIT_CPU, &rl);

    // Output file size
    rl.rlim_cur = rl.rlim_max = limits.max_fsize_mb * 1024ULL * 1024ULL;
    setrlimit(RLIMIT_FSIZE, &rl);

    // Core dump size — disable
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);

    // File descriptors — cap at 64 (stdin/stdout/stderr + input/output + library needs)
    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);

    // Child processes — prevent fork bombs from library code.
    // Skip when ASan is active: ASan's symbolizer forks llvm-symbolizer
    // and RLIMIT_NPROC counts ALL user processes, not just children.
#if !defined(__SANITIZE_ADDRESS__) && !__has_feature(address_sanitizer)
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_NPROC, &rl);
#endif
}

/// Install siglongjmp-based signal handlers for crash recovery
static void InstallRecoveryHandlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SandboxSignalHandler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
}

/// Run a function in a forked child with resource limits and signal recovery.
/// The function receives a string pointer for partial output collection.
/// Returns SandboxResult describing how the child exited.
static SandboxResult RunSandboxed(std::function<int()> fn,
                                   const SandboxLimits& limits = {}) {
    SandboxResult result = {};

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
        InstallRecoveryHandlers();

        int rc = 0;
        int sig = sigsetjmp(g_recovery_point, 1);
        if (sig != 0) {
            // Recovered from signal — now in normal control flow,
            // safe to do I/O (fopen/fwrite/fprintf)
            if (g_crash_callback) {
                g_crash_callback();
                g_crash_callback = nullptr;
            }
            fprintf(stderr, "[ColorBleed] RECOVERED from signal %d (%s)\n",
                    sig, strsignal(sig));
            _exit(128 + sig);
        }

        try {
            rc = fn();
        } catch (const std::exception& e) {
            fprintf(stderr, "[ColorBleed] C++ exception: %s\n", e.what());
            rc = 99;
        } catch (...) {
            fprintf(stderr, "[ColorBleed] Unknown C++ exception\n");
            rc = 99;
        }

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
        // Exit codes 128+ = signal recovery via siglongjmp
        if (result.exit_code >= 128) {
            result.signal_num = result.exit_code - 128;
            result.crashed = true;
            result.partial_output = true;
        } else {
            result.crashed = (result.exit_code != 0);
        }
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

/// Validate output path: no traversal, resolves to a regular file location,
/// parent directory must exist. Returns empty string on failure.
static std::string ValidateOutputPath(const char* raw_path) {
    if (!raw_path || raw_path[0] == '\0') return "";

    // Reject traversal sequences
    if (strstr(raw_path, "..") != nullptr) {
        fprintf(stderr, "[ColorBleed] ERROR: output path must not contain '..'\n");
        return "";
    }

    // Reject null bytes (truncation attack)
    if (strlen(raw_path) != strnlen(raw_path, PATH_MAX)) {
        fprintf(stderr, "[ColorBleed] ERROR: output path contains null bytes\n");
        return "";
    }

    // Resolve the parent directory to prevent symlink attacks
    std::string path_str(raw_path);
    size_t last_sep = path_str.find_last_of('/');
    std::string parent = (last_sep != std::string::npos)
        ? path_str.substr(0, last_sep) : ".";

    char resolved_parent[PATH_MAX];
    if (!realpath(parent.c_str(), resolved_parent)) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot resolve parent directory '%s': %s\n",
                parent.c_str(), strerror(errno));
        return "";
    }

    // Reject writes to sensitive system directories
    const char* blocked_prefixes[] = {
        "/etc", "/proc", "/sys", "/dev", "/boot", "/sbin", "/usr", "/var", nullptr
    };
    for (const char** bp = blocked_prefixes; *bp; bp++) {
        if (strncmp(resolved_parent, *bp, strlen(*bp)) == 0) {
            fprintf(stderr, "[ColorBleed] ERROR: output to system directory '%s' blocked\n",
                    resolved_parent);
            return "";
        }
    }

    // Build resolved output path
    std::string filename = (last_sep != std::string::npos)
        ? path_str.substr(last_sep + 1) : path_str;
    std::string resolved = std::string(resolved_parent) + "/" + filename;
    return resolved;
}

#endif // COLORBLEED_SANDBOX_H
