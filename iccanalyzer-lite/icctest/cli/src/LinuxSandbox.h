/*
 * IccTest CLI — LinuxSandbox.h
 * Linux-native sandboxing: seccomp-bpf, rlimit, prctl.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * Replaces V1's siglongjmp crash recovery with proper fork-based
 * isolation and kernel-level resource limits. The library never calls
 * signal() or setjmp() — crash containment is the CLI's responsibility.
 *
 * Security model:
 *   1. prctl(PR_SET_NO_NEW_PRIVS) — no privilege escalation
 *   2. rlimit RSS/CPU/FSIZE — resource exhaustion prevention
 *   3. seccomp-bpf — syscall whitelist (optional, requires linux/seccomp.h)
 *   4. Fork isolation — parent monitors child, collects exit status
 */

#ifndef ICCTEST_LINUX_SANDBOX_H
#define ICCTEST_LINUX_SANDBOX_H

#include <icctest/CheckResult.h>

#include <cstdint>
#include <functional>
#include <string>
#include <variant>

namespace icctest {

/// Error from sandbox execution.
struct SandboxError {
    enum class Kind : uint8_t {
        ForkFailed,
        Timeout,
        Crashed,
        OOM,
        SeccompViolation,
        InternalError,
    };
    Kind        kind;
    int         signal = 0;      // If crashed, which signal
    std::string message;
};

/// Resource limits for sandboxed execution.
struct SandboxLimits {
    uint64_t maxRSS       = 512ULL * 1024 * 1024;  // 512 MB
    uint64_t maxCPU       = 30;                      // 30 seconds
    uint64_t maxFileSize  = 0;                       // no file writes
    uint64_t maxOpenFiles = 64;
    bool     enableSeccomp = false;  // Off by default (requires kernel support)
    bool     includeConformancePerCheckSummary = false;  // For PAWG formatter
};

/// Apply resource limits and security restrictions to the current process.
/// Called in the child process after fork(). Does NOT fork itself.
void applySandboxLimits(const SandboxLimits& limits);

/// Fork-isolate: run fn() in a child process with resource limits.
/// Returns AnalysisResult on success, SandboxError on child crash/timeout.
std::variant<AnalysisResult, SandboxError>
runSandboxed(std::function<AnalysisResult()> fn,
             const SandboxLimits& limits = {});

/// Check if sandboxing is available on this platform.
bool isSandboxAvailable();

} // namespace icctest

#endif // ICCTEST_LINUX_SANDBOX_H
