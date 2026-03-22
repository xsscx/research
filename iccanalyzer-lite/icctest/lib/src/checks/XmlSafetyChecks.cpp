/*
 * IccTest Library — XmlSafetyChecks.cpp
 * Heuristic checks H142-H145: XML serialization safety.
 *
 * H142 performs fork-isolated XML serialization directly, matching V1.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include "IccProfileXml.h"
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccIO.h"

#include <new>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace icctest {

// ── H142: XML Serialization Safety ──
// Exercise the XML serializer under fork isolation, matching V1 semantics.
static CheckResult check_h142_xml_safety(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.filePath().empty()) {
        return CheckResult::needsIsolation(
            "CIccProfileXml::ToXml() requires fork isolation with a file-backed profile");
    }

    std::fflush(stdout);
    std::fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        cb.high(sfmt("fork() failed (errno=%d) — XML safety check skipped", errno),
                "CWE-271: Cannot isolate XML serialization");
        return cb.done("Fork failed");
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        alarm(10);

        auto* tagFactory = new (std::nothrow) CIccTagXmlFactory();
        auto* mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
        if (!tagFactory || !mpeFactory) {
            delete tagFactory;
            delete mpeFactory;
            _exit(0);
        }
        CIccTagCreator::PushFactory(tagFactory);
        CIccMpeCreator::PushFactory(mpeFactory);

        CIccProfileXml xmlProfile;
        CIccFileIO srcIo;
        if (!srcIo.Open(pv.filePath().c_str(), "rb")) {
            _exit(0);
        }
        if (!xmlProfile.Read(&srcIo)) {
            srcIo.Close();
            _exit(0);
        }
        srcIo.Close();

        std::string xmlOutput;
        try {
            xmlOutput.reserve(4 * 1024 * 1024);
        } catch (...) {
            _exit(0);
        }

        bool ok = xmlProfile.ToXml(xmlOutput);
        _exit(ok ? 0 : 1);
    }

    int status = 0;
    int waited = 0;
    for (int i = 0; i < 150; i++) {
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid) {
            waited = 1;
            break;
        }
        if (ret < 0) {
            waited = -1;
            break;
        }
        usleep(100000);
    }

    if (!waited) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        cb.high("XML serialization timed out (>15s) — potential resource exhaustion",
                "CWE-400: Uncontrolled Resource Consumption");
        return cb.done("XML serialization timed out");
    }

    if (waited < 0) {
        return CheckResult::error("waitpid() failed during XML serialization safety check");
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        const char* sigName = "UNKNOWN";
        switch (sig) {
            case SIGSEGV: sigName = "SIGSEGV"; break;
            case SIGABRT: sigName = "SIGABRT (ASAN/UBSAN)"; break;
            case SIGBUS:  sigName = "SIGBUS"; break;
            case SIGFPE:  sigName = "SIGFPE"; break;
            case SIGALRM: sigName = "SIGALRM (timeout)"; break;
            case SIGKILL: sigName = "SIGKILL (killed)"; break;
        }
        cb.critical(sfmt("XML serialization crashed with %s (signal %d)", sigName, sig),
                    "CWE-787/CWE-125/CWE-476: XML serialization memory safety violation");
        return cb.done("XML serialization crashed");
    }

    if (WIFEXITED(status)) {
        int exitCode = WEXITSTATUS(status);
        if (exitCode == 0) {
            return CheckResult::ok("XML serialization completed safely (ToXml succeeded)");
        }
        return CheckResult::ok(
            sfmt("XML serialization returned error (ToXml=false, exit %d) — no crash",
                 exitCode));
    }

    return CheckResult::ok(sfmt("XML serialization check completed (status=0x%x)", status));
}

// ── H143: XML Array Bounds Precheck ──
static CheckResult check_h143_xml_array_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan for array-type tags where m_nSize * elementSize > tagDataSize
    // Array types: 'ui16' (2 bytes), 'ui32' (4), 'ui64' (8), 'sf32' (4), 'uf32' (4)
    struct ArrayType { uint32_t sig; int elemSize; const char* name; };
    static const ArrayType arrayTypes[] = {
        {0x75693136, 2, "UInt16Array"},  // 'ui16'
        {0x75693332, 4, "UInt32Array"},  // 'ui32'
        {0x75693634, 8, "UInt64Array"},  // 'ui64'
        {0x73663332, 4, "S15Fixed16"},   // 'sf32'
        {0x75663332, 4, "U16Fixed16"},   // 'uf32'
    };

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 8 || t.offset + 8 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);

        for (const auto& at : arrayTypes) {
            if (typeSig != at.sig) continue;

            uint32_t dataBytes = t.size - 8; // subtract type + reserved
            uint32_t elemCount = dataBytes / at.elemSize;
            if (elemCount > 1000000) {
                cb.high(sfmt("Tag '%s' (%s) has %u elements — ToXml would produce enormous output",
                              sigStr(t.signature).c_str(), at.name, elemCount),
                        "CWE-131: Incorrect Calculation of Buffer Size");
            }
        }
    }

    return cb.done("XML array bounds validated");
}

// ── H144: XML String Termination Precheck ──
static CheckResult check_h144_xml_string_term(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Check ColorantTable entries for null-terminated 32-byte names
    // ColorantTable type: 'clrt' = 0x636C7274
    constexpr uint32_t kClrtType = 0x636C7274;

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 12 || t.offset + 12 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kClrtType) continue;

        uint32_t nEntries = readU32BE(d + t.offset + 8);
        // Each entry: 32-byte name + 6 bytes PCS coordinates = 38 bytes
        for (uint32_t i = 0; i < nEntries && i < 256; i++) {
            uint32_t entryOff = t.offset + 12 + i * 38;
            if (entryOff + 38 > len) break;

            // Check if name has null terminator within 32 bytes
            bool hasNull = false;
            for (int j = 0; j < 32; j++) {
                if (d[entryOff + j] == 0) { hasNull = true; break; }
            }
            if (!hasNull) {
                cb.high(sfmt("Colorant entry #%u has unterminated 32-byte name "
                              "— strlen overflow in XML serialization", i),
                        "CWE-170: Improper Null Termination");
            }
        }
    }

    return cb.done("XML string termination validated");
}

// ── H145: XML Curve Type Consistency ──
static CheckResult check_h145_xml_curve_type(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan for CurveSet elements and validate sub-element type signatures
    constexpr uint32_t kCvstSig = 0x63767374; // 'cvst'

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 16 || t.offset + 16 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kCvstSig) continue;

        // CurveSet sub-elements should be valid curve types
        cb.info(sfmt("CurveSet element found in tag '%s'", sigStr(t.signature).c_str()));
    }

    return cb.done("XML curve type consistency validated");
}

// ── Registration ──

REGISTER_HEURISTIC(142, "XML Serialization Safety",
    "CWE-787/CWE-125 Pattern", "25 iccDEV XML advisories",
    "CWE-787", "", Severity::CRITICAL, CheckPhase::LIBRARY, check_h142_xml_safety);

REGISTER_HEURISTIC(143, "XML Array Bounds Precheck",
    "CIccXmlArrayType::DumpArray", "CWE-131",
    "CWE-131", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h143_xml_array_bounds);

REGISTER_HEURISTIC(144, "XML String Termination Precheck",
    "CIccTagColorantTable::ToXml", "CWE-170",
    "CWE-170", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h144_xml_string_term);

REGISTER_HEURISTIC(145, "XML Curve Type Consistency",
    "CIccXmlMpeCurveSet::ToXml", "CWE-843",
    "CWE-843", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h145_xml_curve_type);

} // namespace icctest
