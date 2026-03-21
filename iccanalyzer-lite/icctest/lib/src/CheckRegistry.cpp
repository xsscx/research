/*
 * IccTest Library — CheckRegistry.cpp
 * Self-registering check system implementation.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "icctest/Logger.h"

#include <algorithm>

namespace icctest {

CheckRegistry& CheckRegistry::instance() {
    static CheckRegistry reg;
    return reg;
}

void CheckRegistry::add(RegisteredCheck check) {
    ICCTEST_DEBUG("Registering check %s: %.*s",
        check.id.str().c_str(),
        static_cast<int>(check.meta.name.size()),
        check.meta.name.data());
    m_checks.push_back(std::move(check));
    m_sorted = false;
}

const RegisteredCheck* CheckRegistry::find(const CheckID& id) const {
    for (const auto& c : m_checks) {
        if (c.id == id) return &c;
    }
    return nullptr;
}

std::vector<const RegisteredCheck*> CheckRegistry::byPhase(CheckPhase phase) const {
    std::vector<const RegisteredCheck*> out;
    for (const auto& c : m_checks) {
        if (c.meta.phase == phase) out.push_back(&c);
    }
    return out;
}

std::vector<const RegisteredCheck*> CheckRegistry::byKind(CheckID::Kind kind) const {
    std::vector<const RegisteredCheck*> out;
    for (const auto& c : m_checks) {
        if (c.id.kind == kind) out.push_back(&c);
    }
    return out;
}

void CheckRegistry::sort() {
    if (m_sorted) return;
    std::sort(m_checks.begin(), m_checks.end(),
        [](const RegisteredCheck& a, const RegisteredCheck& b) {
            return a.id < b.id;
        });
    m_sorted = true;
}

void CheckRegistry::clear() {
    m_checks.clear();
    m_sorted = false;
}

} // namespace icctest
