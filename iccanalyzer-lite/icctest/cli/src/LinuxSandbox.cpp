/*
 * IccTest CLI — LinuxSandbox.cpp
 * Linux-native sandboxing: rlimit, prctl, optional seccomp-bpf.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "LinuxSandbox.h"

#include <icctest/CheckRegistry.h>

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

namespace {

Severity maxFindingSeverity(const std::vector<Finding>& findings) {
    Severity worst = Severity::INFO;
    for (const auto& finding : findings) {
        if (finding.level > worst) {
            worst = finding.level;
        }
    }
    return worst;
}

CheckMeta defaultConformanceMeta() {
    return CheckMeta{
        "",
        "",
        "",
        "",
        "",
        Severity::INFO,
        CheckPhase::CONFORMANCE
    };
}

} // namespace

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
    // Runtime fallback: if compile-time detection missed (e.g., sanitizer
    // flags applied only at link time), check ASAN_OPTIONS env var or
    // probe for ASAN's interceptor symbol via weak reference.
    if (!asanActive && std::getenv("ASAN_OPTIONS")) {
        asanActive = true;
    }
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

        // Binary protocol for result transfer:
        // [4B: magic 'ICT\0']
        // [ProfileMetadata: 7*4B fixed + 8B fileSize + 16B profileId + 4B magic + 12B illuminant + 4B creatorLen + creator]
        // [4B: findingsTotal] [4B: checksRun] [4B: checksSkipped] [8B: totalTime_us]
        // [5*4B: findingsBySeverity]
        // [4B: nFindings] [N * Finding: sev(1) + kind(1) + num(4) + 3 strings]
        // [4B: nPerCheck] [N * PerCheckSummary: kind(1) + num(4) + status(1) +
        //                                    worstSeverity(1) + findingCount(4) + summary]
        uint8_t magic[4] = {'I', 'C', 'T', '\0'};
        (void)write(pipefd[1], magic, 4);

        // ProfileMetadata (fixed-size fields)
        auto& md = result.metadata;
        (void)write(pipefd[1], &md.version, 4);
        (void)write(pipefd[1], &md.profileClass, 4);
        (void)write(pipefd[1], &md.colorSpace, 4);
        (void)write(pipefd[1], &md.pcs, 4);
        (void)write(pipefd[1], &md.flags, 4);
        (void)write(pipefd[1], &md.headerSize, 4);
        (void)write(pipefd[1], &md.fileSize, 8);
        (void)write(pipefd[1], &md.renderingIntent, 4);
        (void)write(pipefd[1], &md.manufacturer, 4);
        (void)write(pipefd[1], &md.model, 4);
        (void)write(pipefd[1], md.profileId.data(), 16);
        (void)write(pipefd[1], md.magic.data(), 4);
        (void)write(pipefd[1], md.illuminant.data(), 12);
        int32_t creatorLen = static_cast<int32_t>(md.creator.size());
        (void)write(pipefd[1], &creatorLen, 4);
        if (creatorLen > 0) (void)write(pipefd[1], md.creator.data(), creatorLen);

        // RunStats
        int32_t findingsTotal = result.stats.findingsTotal;
        int32_t checksRun = result.stats.checksRun;
        int32_t checksSkipped = result.stats.checksSkipped;
        int64_t totalTime = result.stats.totalTime.count();

        (void)write(pipefd[1], &findingsTotal, 4);
        (void)write(pipefd[1], &checksRun, 4);
        (void)write(pipefd[1], &checksSkipped, 4);
        (void)write(pipefd[1], &totalTime, 8);
        (void)write(pipefd[1], result.stats.findingsBySeverity.data(),
                    5 * sizeof(int32_t));

        // Findings
        int32_t nFindings = static_cast<int32_t>(result.findings.size());
        (void)write(pipefd[1], &nFindings, 4);

        auto writeStr = [&](const std::string& s) {
            int32_t len = static_cast<int32_t>(s.size());
            (void)write(pipefd[1], &len, 4);
            if (len > 0) (void)write(pipefd[1], s.data(), len);
        };

        for (const auto& f : result.findings) {
            uint8_t sev = static_cast<uint8_t>(f.level);
            (void)write(pipefd[1], &sev, 1);

            uint8_t kind = static_cast<uint8_t>(f.id.kind);
            int32_t num = f.id.number;
            (void)write(pipefd[1], &kind, 1);
            (void)write(pipefd[1], &num, 4);

            writeStr(f.message);
            writeStr(f.detail);
            writeStr(f.cweNote);
        }

        int32_t nPerCheck = 0;
        if (limits.includeConformancePerCheckSummary) {
            for (const auto& entry : result.perCheck) {
                if (entry.id.kind == CheckID::Kind::Conformance) {
                    ++nPerCheck;
                }
            }
        }
        (void)write(pipefd[1], &nPerCheck, 4);

        if (nPerCheck > 0) {
            for (const auto& entry : result.perCheck) {
                if (entry.id.kind != CheckID::Kind::Conformance) {
                    continue;
                }

                uint8_t kind = static_cast<uint8_t>(entry.id.kind);
                int32_t num = entry.id.number;
                uint8_t status = static_cast<uint8_t>(entry.result.status);
                uint8_t worstSeverity = static_cast<uint8_t>(maxFindingSeverity(entry.result.findings));
                int32_t findingCount = static_cast<int32_t>(entry.result.findings.size());

                (void)write(pipefd[1], &kind, 1);
                (void)write(pipefd[1], &num, 4);
                (void)write(pipefd[1], &status, 1);
                (void)write(pipefd[1], &worstSeverity, 1);
                (void)write(pipefd[1], &findingCount, 4);
                writeStr(entry.result.summary);
            }
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

    // ProfileMetadata (fixed-size fields)
    auto& md = result.metadata;
    (void)read(pipefd[0], &md.version, 4);
    (void)read(pipefd[0], &md.profileClass, 4);
    (void)read(pipefd[0], &md.colorSpace, 4);
    (void)read(pipefd[0], &md.pcs, 4);
    (void)read(pipefd[0], &md.flags, 4);
    (void)read(pipefd[0], &md.headerSize, 4);
    (void)read(pipefd[0], &md.fileSize, 8);
    (void)read(pipefd[0], &md.renderingIntent, 4);
    (void)read(pipefd[0], &md.manufacturer, 4);
    (void)read(pipefd[0], &md.model, 4);
    (void)read(pipefd[0], md.profileId.data(), 16);
    (void)read(pipefd[0], md.magic.data(), 4);
    (void)read(pipefd[0], md.illuminant.data(), 12);
    int32_t creatorLen = 0;
    (void)read(pipefd[0], &creatorLen, 4);
    if (creatorLen > 0 && creatorLen < 256) {
        md.creator.resize(creatorLen);
        (void)read(pipefd[0], md.creator.data(), creatorLen);
    }

    // RunStats
    int32_t findingsTotal = 0, checksRun = 0, checksSkipped = 0;
    int64_t totalTime = 0;
    (void)read(pipefd[0], &findingsTotal, 4);
    (void)read(pipefd[0], &checksRun, 4);
    (void)read(pipefd[0], &checksSkipped, 4);
    (void)read(pipefd[0], &totalTime, 8);
    (void)read(pipefd[0], result.stats.findingsBySeverity.data(),
               5 * sizeof(int32_t));

    result.stats.findingsTotal = findingsTotal;
    result.stats.checksRun = checksRun;
    result.stats.checksSkipped = checksSkipped;
    result.stats.totalTime = std::chrono::microseconds(totalTime);

    // Findings
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

    int32_t nPerCheck = 0;
    if (read(pipefd[0], &nPerCheck, 4) == 4 && nPerCheck > 0) {
        if (nPerCheck > 4096) nPerCheck = 4096;
        result.perCheck.reserve(static_cast<size_t>(nPerCheck));

        for (int32_t i = 0; i < nPerCheck; ++i) {
            uint8_t kind = 0;
            int32_t num = 0;
            uint8_t status = 0;
            uint8_t worstSeverity = 0;
            int32_t findingCount = 0;

            if (read(pipefd[0], &kind, 1) != 1) break;
            if (read(pipefd[0], &num, 4) != 4) break;
            if (read(pipefd[0], &status, 1) != 1) break;
            if (read(pipefd[0], &worstSeverity, 1) != 1) break;
            if (read(pipefd[0], &findingCount, 4) != 4) break;

            PerCheckResult entry{};
            entry.id = {static_cast<CheckID::Kind>(kind & 1), num};
            if (const auto* reg = CheckRegistry::instance().find(entry.id)) {
                entry.meta = reg->meta;
            } else {
                entry.meta = defaultConformanceMeta();
            }

            entry.result.status = static_cast<CheckResult::Status>(std::min<uint8_t>(status, 4));
            entry.result.summary = readStr();

            if (findingCount > 0) {
                if (findingCount > 1024) findingCount = 1024;
                entry.result.findings.reserve(static_cast<size_t>(findingCount));
                const auto worst = static_cast<Severity>(std::min<uint8_t>(worstSeverity, 4));
                for (int32_t j = 0; j < findingCount; ++j) {
                    entry.result.findings.push_back(Finding{
                        entry.id,
                        j == 0 ? worst : Severity::INFO,
                        "",
                        "",
                        ""
                    });
                }
            }

            result.perCheck.push_back(std::move(entry));
        }
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
