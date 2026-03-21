/*
 * IccTest Library — CheckRegistry.h
 * Self-registering check system.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * Checks register themselves via the REGISTER_CHECK macro at static
 * initialization time. The registry owns all check metadata and function
 * pointers. Adding a new check = 1 function + 1 macro invocation.
 */

#ifndef ICCTEST_CHECK_REGISTRY_H
#define ICCTEST_CHECK_REGISTRY_H

#include "CheckResult.h"
#include "ProfileView.h"

#include <functional>
#include <string_view>
#include <vector>
#include <unordered_map>

namespace icctest {

/// A registered check: metadata + function pointer.
struct RegisteredCheck {
    CheckID   id;
    CheckMeta meta;
    std::function<CheckResult(const ProfileView&)> fn;
};

/// Central registry of all checks. Populated at static init time.
class CheckRegistry {
public:
    /// Get the global registry instance.
    static CheckRegistry& instance();

    /// Register a check (called by REGISTER_CHECK macro at static init).
    void add(RegisteredCheck check);

    /// Get all registered checks, ordered by (kind, number).
    const std::vector<RegisteredCheck>& all() const { return m_checks; }

    /// Look up a check by ID.
    const RegisteredCheck* find(const CheckID& id) const;

    /// Number of registered checks.
    size_t size() const { return m_checks.size(); }

    /// Get all checks for a specific phase.
    std::vector<const RegisteredCheck*> byPhase(CheckPhase phase) const;

    /// Get all checks for a specific kind (heuristic or conformance).
    std::vector<const RegisteredCheck*> byKind(CheckID::Kind kind) const;

    /// Sort checks by (kind, number) — called after all static init.
    void sort();

    /// Clear all checks (for testing).
    void clear();

private:
    CheckRegistry() = default;
    std::vector<RegisteredCheck> m_checks;
    mutable bool m_sorted = false;
};

/// Helper for static registration. Constructed at file scope by REGISTER_CHECK.
struct CheckRegistrar {
    CheckRegistrar(RegisteredCheck check) {
        CheckRegistry::instance().add(std::move(check));
    }
};

} // namespace icctest

// ── REGISTER_CHECK macro ──
//
// Usage:
//   CheckResult check_cf317_htos_consistency(const ProfileView& pv) { ... }
//
//   REGISTER_HEURISTIC(42, "Profile Size Validation",
//       "ICC.1-2022-05 §7.2.2", "ICC.1-2022-05",
//       "CWE-131", "", Severity::HIGH, CheckPhase::HEADER,
//       check_h42_profile_size);
//
//   REGISTER_CONFORMANCE(317, "HToS Flag-Tag Consistency",
//       "ICC.2-2023 Annex K.2.9", "ICC.2-2023",
//       "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
//       check_cf317_htos_consistency);

#define ICCTEST_REGISTER_CHECK_(kind_val, num, name, specRef, specDoc,       \
                                cwe, cve, sev, phase, func)                   \
    static ::icctest::CheckRegistrar g_reg_##kind_val##_##num{                \
        ::icctest::RegisteredCheck{                                           \
            {::icctest::CheckID::Kind::kind_val, num},                        \
            {name, specRef, specDoc, cwe, cve, sev, phase},                   \
            func                                                              \
        }                                                                     \
    }

#define REGISTER_HEURISTIC(num, name, specRef, specDoc, cwe, cve, sev, phase, func) \
    ICCTEST_REGISTER_CHECK_(Heuristic, num, name, specRef, specDoc, cwe, cve, sev, phase, func)

#define REGISTER_CONFORMANCE(num, name, specRef, specDoc, cwe, cve, sev, phase, func) \
    ICCTEST_REGISTER_CHECK_(Conformance, num, name, specRef, specDoc, cwe, cve, sev, phase, func)

#endif // ICCTEST_CHECK_REGISTRY_H
