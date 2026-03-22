/*
 * IccTest CLI — LinuxSandbox.cpp
 * Linux-native sandboxing: rlimit, prctl, optional seccomp-bpf.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "LinuxSandbox.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#ifdef __linux__
#include <unistd.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#endif

namespace icctest {

bool isSandboxAvailable() {
#ifdef __linux__
    return true;
#else
    return false;
#endif
}

void applySandboxLimits(const SandboxLimits& limits) {
#ifdef __linux__
    // 1. No new privileges — cannot exec setuid binaries
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::fprintf(stderr, "[sandbox] prctl(NO_NEW_PRIVS) failed: %s\n",
                     std::strerror(errno));
    }

    // 2. Not dumpable — no ptrace attachment, no core dumps in /proc
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // 3. Memory limits — strategy depends on ASAN presence.
    // ASAN maps ~20TB of virtual address space for shadow memory.
    // RLIMIT_AS would prevent mmap and kill the child immediately.
    // RLIMIT_DATA also breaks ASAN (its allocator uses mmap, not brk).
    // When ASAN is active, memory limiting is handled by the PARENT
    // process via RSS polling in runSandboxed() — see below.
    // Without ASAN, RLIMIT_AS is the tightest constraint.
    struct rlimit rl;
    bool asanActive = false;
#if defined(__SANITIZE_ADDRESS__)
    asanActive = true;
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
    asanActive = true;
#  endif
#endif
    if (!asanActive) {
        rl.rlim_cur = limits.maxRSS;
        rl.rlim_max = limits.maxRSS;
        setrlimit(RLIMIT_AS, &rl);
    }

    // 4. CPU time limit
    rl.rlim_cur = limits.maxCPU;
    rl.rlim_max = limits.maxCPU + 5;  // Hard limit 5s after soft
    setrlimit(RLIMIT_CPU, &rl);

    // 5. No file creation
    rl.rlim_cur = limits.maxFileSize;
    rl.rlim_max = limits.maxFileSize;
    setrlimit(RLIMIT_FSIZE, &rl);

    // 6. Limit open file descriptors
    rl.rlim_cur = limits.maxOpenFiles;
    rl.rlim_max = limits.maxOpenFiles;
    setrlimit(RLIMIT_NOFILE, &rl);

    // 7. No core dumps
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);

    // 8. Seccomp-bpf (optional — requires kernel headers)
    // Deferred: seccomp filter needs careful syscall audit for iccDEV's
    // use of mmap, mprotect, futex, clone, etc. Enable in future releases.
    (void)limits.enableSeccomp;

#else
    (void)limits;
    // Non-Linux: no sandbox, best-effort only
#endif
}

std::variant<AnalysisResult, SandboxError>
runSandboxed(std::function<AnalysisResult()> fn,
             const SandboxLimits& limits) {
#ifdef __linux__
    // Pipes for result transfer: child writes serialized result, parent reads
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return SandboxError{SandboxError::Kind::ForkFailed, 0,
                            std::string("pipe() failed: ") + std::strerror(errno)};
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return SandboxError{SandboxError::Kind::ForkFailed, 0,
                            std::string("fork() failed: ") + std::strerror(errno)};
    }

    if (pid == 0) {
        // ─── Child process ───
        close(pipefd[0]);  // Close read end

        applySandboxLimits(limits);

        // Run the analysis
        AnalysisResult result;
        try {
            result = fn();
        } catch (const std::exception& e) {
            result.findings.push_back(Finding{
                {CheckID::Kind::Heuristic, 0},
                Severity::CRITICAL,
                std::string("Analysis threw exception: ") + e.what(),
                "", ""
            });
            result.stats.findingsTotal = 1;
            result.stats.findingsBySeverity[4] = 1;
        } catch (...) {
            result.findings.push_back(Finding{
                {CheckID::Kind::Heuristic, 0},
                Severity::CRITICAL,
                "Analysis threw unknown exception",
                "", ""
            });
            result.stats.findingsTotal = 1;
            result.stats.findingsBySeverity[4] = 1;
        }

        // Write a simple success marker + stats to parent
        // Full result transfer uses a minimal binary protocol:
        // [4 bytes: magic 'ICT\0'] [4 bytes: findingsTotal] [4 bytes: checksRun]
        // [4 bytes: checksSkipped] [8 bytes: totalTime_us]
        // [N * Finding: severity(1) + msgLen(4) + msg]
        uint8_t magic[4] = {'I', 'C', 'T', '\0'};
        (void)write(pipefd[1], magic, 4);

        int32_t findingsTotal = result.stats.findingsTotal;
        int32_t checksRun = result.stats.checksRun;
        int32_t checksSkipped = result.stats.checksSkipped;
        int64_t totalTime = result.stats.totalTime.count();

        (void)write(pipefd[1], &findingsTotal, 4);
        (void)write(pipefd[1], &checksRun, 4);
        (void)write(pipefd[1], &checksSkipped, 4);
        (void)write(pipefd[1], &totalTime, 8);

        // Write findings count + each finding
        int32_t nFindings = static_cast<int32_t>(result.findings.size());
        (void)write(pipefd[1], &nFindings, 4);

        for (const auto& f : result.findings) {
            uint8_t sev = static_cast<uint8_t>(f.level);
            (void)write(pipefd[1], &sev, 1);

            auto writeStr = [&](const std::string& s) {
                int32_t len = static_cast<int32_t>(s.size());
                (void)write(pipefd[1], &len, 4);
                if (len > 0) (void)write(pipefd[1], s.data(), len);
            };

            // Write check ID
            uint8_t kind = static_cast<uint8_t>(f.id.kind);
            int32_t num = f.id.number;
            (void)write(pipefd[1], &kind, 1);
            (void)write(pipefd[1], &num, 4);

            writeStr(f.message);
            writeStr(f.detail);
            writeStr(f.cweNote);
        }

        close(pipefd[1]);
        _exit(result.hasCritical() ? 1 : 0);
    }

    // ─── Parent process ───
    close(pipefd[1]);  // Close write end

    // Wait for child with RSS monitoring.
    // Under ASAN, RLIMIT_AS/DATA can't limit memory, so we poll
    // /proc/<pid>/statm and kill the child if RSS exceeds the limit.
    // RSS limit: 4 GB physical (enough for any legitimate ICC profile).
    constexpr uint64_t kMaxRSSPages = (4ULL * 1024 * 1024 * 1024) / 4096;
    int status = 0;
    pid_t waited = 0;

    while (true) {
        waited = waitpid(pid, &status, WNOHANG);
        if (waited != 0) break;  // Child exited or error

        // Check child RSS via /proc/pid/statm (field 2 = RSS in pages)
        char statmPath[64];
        std::snprintf(statmPath, sizeof(statmPath), "/proc/%d/statm", pid);
        FILE* statm = std::fopen(statmPath, "r");
        if (statm) {
            unsigned long vmSize = 0, rss = 0;
            if (std::fscanf(statm, "%lu %lu", &vmSize, &rss) == 2) {
                if (rss > kMaxRSSPages) {
                    kill(pid, SIGKILL);
                    waitpid(pid, &status, 0);
                    std::fclose(statm);
                    close(pipefd[0]);
                    return SandboxError{SandboxError::Kind::OOM, SIGKILL,
                        "Child exceeded 4 GB RSS limit (killed by sandbox)"};
                }
            }
            std::fclose(statm);
        }

        // Poll every 50ms
        usleep(50000);
    }

    if (waited < 0) {
        close(pipefd[0]);
        return SandboxError{SandboxError::Kind::InternalError, 0,
                            std::string("waitpid() failed: ") + std::strerror(errno)};
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        close(pipefd[0]);

        SandboxError::Kind kind = SandboxError::Kind::Crashed;
        std::string msg = "Child killed by signal " + std::to_string(sig);

        if (sig == SIGKILL) {
            kind = SandboxError::Kind::OOM;
            msg = "Child killed by SIGKILL (likely OOM)";
        } else if (sig == SIGXCPU) {
            kind = SandboxError::Kind::Timeout;
            msg = "Child exceeded CPU time limit";
        } else if (sig == SIGSYS) {
            kind = SandboxError::Kind::SeccompViolation;
            msg = "Child made disallowed syscall (seccomp)";
        }

        return SandboxError{kind, sig, msg};
    }

    // Child exited normally — read result from pipe
    AnalysisResult result{};

    uint8_t magic[4] = {};
    ssize_t nr = read(pipefd[0], magic, 4);
    if (nr != 4 || magic[0] != 'I' || magic[1] != 'C' || magic[2] != 'T') {
        close(pipefd[0]);
        return SandboxError{SandboxError::Kind::InternalError, 0,
                            "Failed to read result from child (bad magic)"};
    }

    int32_t findingsTotal = 0, checksRun = 0, checksSkipped = 0;
    int64_t totalTime = 0;
    (void)read(pipefd[0], &findingsTotal, 4);
    (void)read(pipefd[0], &checksRun, 4);
    (void)read(pipefd[0], &checksSkipped, 4);
    (void)read(pipefd[0], &totalTime, 8);

    result.stats.findingsTotal = findingsTotal;
    result.stats.checksRun = checksRun;
    result.stats.checksSkipped = checksSkipped;
    result.stats.totalTime = std::chrono::microseconds(totalTime);

    int32_t nFindings = 0;
    (void)read(pipefd[0], &nFindings, 4);

    // Cap findings to prevent malformed data from exhausting memory
    if (nFindings > 10000) nFindings = 10000;

    auto readStr = [&]() -> std::string {
        int32_t len = 0;
        if (read(pipefd[0], &len, 4) != 4 || len < 0 || len > 1000000) return {};
        std::string s(len, '\0');
        if (len > 0) {
            ssize_t got = read(pipefd[0], s.data(), len);
            if (got != len) s.resize(std::max<ssize_t>(0, got));
        }
        return s;
    };

    for (int32_t i = 0; i < nFindings; ++i) {
        Finding f{};
        uint8_t sev = 0;
        if (read(pipefd[0], &sev, 1) != 1) break;
        f.level = static_cast<Severity>(std::min<uint8_t>(sev, 4));

        uint8_t kind = 0;
        int32_t num = 0;
        if (read(pipefd[0], &kind, 1) != 1) break;
        if (read(pipefd[0], &num, 4) != 4) break;
        f.id = {static_cast<CheckID::Kind>(kind & 1), num};

        f.message = readStr();
        f.detail  = readStr();
        f.cweNote = readStr();

        result.findings.push_back(std::move(f));
    }

    close(pipefd[0]);
    return result;

#else
    // Non-Linux: run in-process (no sandbox)
    (void)limits;
    try {
        return fn();
    } catch (const std::exception& e) {
        return SandboxError{SandboxError::Kind::InternalError, 0,
                            std::string("Analysis failed: ") + e.what()};
    }
#endif
}

} // namespace icctest
