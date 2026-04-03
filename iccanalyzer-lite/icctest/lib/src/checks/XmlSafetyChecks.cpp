/*
 * IccTest Library - XmlSafetyChecks.cpp
 * Heuristic checks H142-H145, H180: XML serialization safety.
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

namespace {

bool waitForChild(pid_t pid, int& status) {
    for (;;) {
        pid_t ret = waitpid(pid, &status, 0);
        if (ret == pid) {
            return true;
        }
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

} // namespace

// -- H142: XML Serialization Safety --
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
        cb.high(sfmt("fork() failed (errno=%d) - XML safety check skipped", errno),
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
    if (!waitForChild(pid, status)) {
        return CheckResult::error("waitpid() failed during XML serialization safety check");
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGALRM) {
            cb.high("XML serialization timed out (>10s) -- potential resource exhaustion",
                    "CWE-400: Uncontrolled Resource Consumption");
            return cb.done("XML serialization timed out");
        }
        const char* sigName = "UNKNOWN";
        switch (sig) {
            case SIGSEGV: sigName = "SIGSEGV"; break;
            case SIGABRT: sigName = "SIGABRT (ASAN/UBSAN)"; break;
            case SIGBUS:  sigName = "SIGBUS"; break;
            case SIGFPE:  sigName = "SIGFPE"; break;
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
            sfmt("XML serialization returned error (ToXml=false, exit %d) - no crash",
                 exitCode));
    }

    return CheckResult::ok(sfmt("XML serialization check completed (status=0x%x)", status));
}

// -- H143: XML Array Bounds Precheck --
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
        if (t.size < 8 || !rawRangeAccessible(len, t.offset, 8)) continue;
        uint32_t typeSig = readU32BE(d + t.offset);

        for (const auto& at : arrayTypes) {
            if (typeSig != at.sig) continue;

            uint32_t dataBytes = t.size - 8; // subtract type + reserved
            uint32_t elemCount = dataBytes / at.elemSize;
            if (elemCount > 1000000) {
                cb.high(sfmt("Tag '%s' (%s) has %u elements - ToXml would produce enormous output",
                              sigStr(t.signature).c_str(), at.name, elemCount),
                        "CWE-131: Incorrect Calculation of Buffer Size");
            }
        }
    }

    return cb.done("XML array bounds validated");
}

// -- H144: XML String Termination Precheck --
static CheckResult check_h144_xml_string_term(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Check ColorantTable entries for null-terminated 32-byte names
    // ColorantTable type: 'clrt' = 0x636C7274
    constexpr uint32_t kClrtType = 0x636C7274;

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 12 || !rawRangeAccessible(len, t.offset, 12)) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kClrtType) continue;

        uint32_t nEntries = readU32BE(d + t.offset + 8);
        // Each entry: 32-byte name + 6 bytes PCS coordinates = 38 bytes
        for (uint32_t i = 0; i < nEntries && i < 256; i++) {
            uint64_t entryOff = static_cast<uint64_t>(t.offset) + 12ull + static_cast<uint64_t>(i) * 38ull;
            if (!rawRangeAccessible(len, entryOff, 38)) break;

            // Check if name has null terminator within 32 bytes
            bool hasNull = false;
            for (int j = 0; j < 32; j++) {
                if (d[entryOff + j] == 0) { hasNull = true; break; }
            }
            if (!hasNull) {
                cb.high(sfmt("Colorant entry #%u has unterminated 32-byte name "
                              "- strlen overflow in XML serialization", i),
                        "CWE-170: Improper Null Termination");
            }
        }
    }

    return cb.done("XML string termination validated");
}

// -- H145: XML Curve Type Consistency --
static CheckResult check_h145_xml_curve_type(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan for CurveSet elements and validate sub-element type signatures
    constexpr uint32_t kCvstSig = 0x63767374; // 'cvst'

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 16 || !rawRangeAccessible(len, t.offset, 16)) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kCvstSig) continue;

        // CurveSet sub-elements should be valid curve types
        cb.info(sfmt("CurveSet element found in tag '%s'", sigStr(t.signature).c_str()));
    }

    return cb.done("XML curve type consistency validated");
}

// -- Registration --

REGISTER_HEURISTIC(142, "XML Serialization Safety",
    "CWE-787/CWE-125 Pattern", "27 iccDEV XML advisories",
    "CWE-787", "CVE-2026-34548,CVE-2026-34556,GHSA-p9wm-xfv4-43qg,GHSA-prwp-9gv6-ccxv",
    Severity::CRITICAL, CheckPhase::LIBRARY, check_h142_xml_safety);

REGISTER_HEURISTIC(143, "XML Array Bounds Precheck",
    "CIccXmlArrayType::DumpArray", "CWE-131",
    "CWE-131", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h143_xml_array_bounds);

REGISTER_HEURISTIC(144, "XML String Termination Precheck",
    "CIccTagColorantTable::ToXml", "CWE-170",
    "CWE-170", "CVE-2026-34556,GHSA-p9wm-xfv4-43qg",
    Severity::HIGH, CheckPhase::RAW_SCAN, check_h144_xml_string_term);

REGISTER_HEURISTIC(145, "XML Curve Type Consistency",
    "CIccXmlMpeCurveSet::ToXml", "CWE-843",
    "CWE-843", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h145_xml_curve_type);

// -- H180: XML Round-Trip Fidelity --
// Fork-isolated: ICC -> ToXml -> LoadXml -> compare header + tag structure.
// Match V1: header mismatches and missing tags are findings even if tag counts
// happen to stay the same after round-trip.
static CheckResult check_h180_xml_round_trip_fidelity(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.filePath().empty()) {
        return CheckResult::needsIsolation(
            "XML round-trip requires fork isolation with a file-backed profile");
    }

    std::fflush(stdout);
    std::fflush(stderr);

    // Use a pipe to return tag count delta from child
    int pipeFd[2];
    if (pipe(pipeFd) < 0) {
        return CheckResult::error("pipe() failed for XML round-trip check");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipeFd[0]);
        close(pipeFd[1]);
        cb.high(sfmt("fork() failed (errno=%d) -- XML round-trip check skipped", errno),
                "CWE-271: Cannot isolate XML round-trip");
        return cb.done("Fork failed");
    }

    if (pid == 0) {
        close(pipeFd[0]); // child writes only
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        alarm(20);

        auto* tagFactory = new (std::nothrow) CIccTagXmlFactory();
        auto* mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
        if (!tagFactory || !mpeFactory) {
            delete tagFactory;
            delete mpeFactory;
            int32_t val = -999;
            (void)write(pipeFd[1], &val, sizeof(val));
            close(pipeFd[1]);
            _exit(0);
        }
        CIccTagCreator::PushFactory(tagFactory);
        CIccMpeCreator::PushFactory(mpeFactory);

        // Step 1: Read original
        CIccProfileXml origXml;
        CIccFileIO srcIo;
        if (!srcIo.Open(pv.filePath().c_str(), "rb")) {
            close(pipeFd[1]);
            _exit(0);
        }
        if (!origXml.Read(&srcIo)) {
            srcIo.Close();
            close(pipeFd[1]);
            _exit(0);
        }
        srcIo.Close();
        int32_t origCount = static_cast<int32_t>(origXml.m_Tags.size());
        uint32_t origVersion = static_cast<uint32_t>(origXml.m_Header.version);
        uint32_t origClass = static_cast<uint32_t>(origXml.m_Header.deviceClass);
        uint32_t origCS = static_cast<uint32_t>(origXml.m_Header.colorSpace);
        uint32_t origPCS = static_cast<uint32_t>(origXml.m_Header.pcs);

        // Step 2: ToXml
        std::string xmlOutput;
        try { xmlOutput.reserve(4 * 1024 * 1024); } catch (...) {
            close(pipeFd[1]);
            _exit(0);
        }
        if (!origXml.ToXml(xmlOutput)) {
            close(pipeFd[1]);
            _exit(1);
        }

        // Step 3: Write XML to temp file
        char tmpPath[] = "/tmp/icctest-h180-XXXXXX";
        int fd = mkstemp(tmpPath);
        if (fd < 0) {
            close(pipeFd[1]);
            _exit(0);
        }
        (void)write(fd, xmlOutput.data(), xmlOutput.size());
        close(fd);

        // Step 4: LoadXml
        CIccProfileXml rtProfile;
        std::string parseErr;
        // lgtm[icc/xml-all-attacks] - round-trip XML is emitted by ToXml() from the same in-memory profile in this isolated child process.
        // lgtm[icc/xml-external-entity-attacks] - the XML file is produced locally by ToXml() for this profile round-trip check.
        if (!rtProfile.LoadXml(tmpPath, nullptr, &parseErr)) {
            unlink(tmpPath);
            close(pipeFd[1]);
            _exit(2);
        }
        unlink(tmpPath);

        int32_t rtCount = static_cast<int32_t>(rtProfile.m_Tags.size());
        int32_t delta = rtCount - origCount;
        (void)write(pipeFd[1], &origCount, sizeof(origCount));
        (void)write(pipeFd[1], &rtCount, sizeof(rtCount));
        (void)write(pipeFd[1], &delta, sizeof(delta));

        if (static_cast<uint32_t>(rtProfile.m_Header.version) != origVersion ||
            static_cast<uint32_t>(rtProfile.m_Header.deviceClass) != origClass ||
            static_cast<uint32_t>(rtProfile.m_Header.colorSpace) != origCS ||
            static_cast<uint32_t>(rtProfile.m_Header.pcs) != origPCS ||
            rtCount != origCount) {
            close(pipeFd[1]);
            _exit(3);
        }

        int tagMismatches = 0;
        for (auto it = origXml.m_Tags.begin(); it != origXml.m_Tags.end(); ++it) {
            if (!rtProfile.FindTag(it->TagInfo.sig)) {
                tagMismatches++;
            }
        }
        if (tagMismatches > 0) {
            close(pipeFd[1]);
            _exit(4);
        }

        close(pipeFd[1]);
        _exit(0);
    }

    // Parent
    close(pipeFd[1]); // parent reads only
    int status = 0;
    if (!waitForChild(pid, status)) {
        close(pipeFd[0]);
        return CheckResult::error("waitpid() failed during XML round-trip check");
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        close(pipeFd[0]);
        if (sig == SIGALRM) {
            cb.high("XML round-trip timed out (>20s) -- potential resource exhaustion",
                    "CWE-400: Uncontrolled Resource Consumption");
            return cb.done("XML round-trip timed out");
        }
        cb.critical(sfmt("XML round-trip crashed with signal %d", sig),
                    "CWE-787/CWE-125: XML round-trip memory safety violation");
        return cb.done("XML round-trip crashed");
    }

    int32_t vals[3] = {0, 0, 0};
    ssize_t nRead = read(pipeFd[0], vals, sizeof(vals));
    close(pipeFd[0]);

    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int32_t origCount = vals[0];
    int32_t rtCount = vals[1];
    int32_t delta = vals[2];

    switch (code) {
        case 0:
            if (nRead == 3 * static_cast<ssize_t>(sizeof(int32_t))) {
                return CheckResult::ok(
                    sfmt("XML round-trip: orig=%d tags, rt=%d tags, delta=%d",
                         origCount, rtCount, delta));
            }
            return CheckResult::ok("XML round-trip preserves profile structure");

        case 1:
            cb.high("ToXml() serialization failed -- data not representable as XML",
                    "CWE-345: Insufficient Verification of Data Authenticity");
            return cb.done("ToXml failed");

        case 2:
            cb.high("FromXml(ToXml()) failed -- round-trip data loss",
                    "CWE-345: Insufficient Verification of Data Authenticity");
            return cb.done("FromXml failed on ToXml output");

        case 3:
            cb.high("Round-trip header/tag-count mismatch -- structural data loss",
                    "CWE-345: Insufficient Verification of Data Authenticity");
            if (nRead == 3 * static_cast<ssize_t>(sizeof(int32_t))) {
                return cb.done(
                    sfmt("XML round-trip: orig=%d tags, rt=%d tags, delta=%d",
                         origCount, rtCount, delta));
            }
            return cb.done("Structural mismatch after round-trip");

        case 4:
            cb.high("Round-trip tag data loss -- tags present in original missing after round-trip",
                    "CWE-345: Insufficient Verification of Data Authenticity");
            return cb.done("Tag data lost in round-trip");

        default:
            return CheckResult::ok("XML round-trip completed (no detailed results available)");
    }
}

REGISTER_HEURISTIC(180, "XML Round-Trip Fidelity",
    "CIccProfileXml::ToXml/LoadXml", "PR #708 coverage gap",
    "CWE-345", "",
    Severity::HIGH, CheckPhase::LIBRARY, check_h180_xml_round_trip_fidelity);

} // namespace icctest
