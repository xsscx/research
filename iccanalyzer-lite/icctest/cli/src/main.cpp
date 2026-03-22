/*
 * IccTest CLI — main.cpp
 * Entry point for the icctest CLI tool.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * Ties together: ArgParser → IccTestRunner → OutputFormatter → LinuxSandbox.
 *
 * Exit codes:
 *   0 = No findings
 *   1 = Findings detected
 *   2 = Error (bad input, missing file)
 *   3 = Usage error
 */

#include "ArgParser.h"
#include "LinuxSandbox.h"
#include "OutputFormatter.h"

#include <icctest/IccTest.h>
#include <icctest/CheckRegistry.h>
#include <icctest/Logger.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <memory>
#include <cstdio>
#include <cstdlib>

namespace icctest {
// Factory functions defined in formatters/*.cpp
std::unique_ptr<OutputFormatter> createTextFormatter();
std::unique_ptr<OutputFormatter> createJsonFormatter();
std::unique_ptr<OutputFormatter> createSarifFormatter();
} // namespace icctest

// ASAN/UBSAN runtime configuration
extern "C" const char* __asan_default_options() {
    return "halt_on_error=0:detect_leaks=0:print_stats=0:log_path=stderr";
}

extern "C" const char* __ubsan_default_options() {
    return "halt_on_error=0:print_stacktrace=1:silence_unsigned_overflow=1";
}

static constexpr const char* kVersion = "2.0.0";

int main(int argc, char** argv) {
    using namespace icctest;

#if defined(__GNUC__)
    if (!std::getenv("GCOV_PREFIX")) {
        setenv("GCOV_PREFIX", "/tmp/icctest-gcov-cli", 0);
        setenv("GCOV_PREFIX_STRIP", "0", 0);
    }
#endif

    auto args = parseArgs(argc, argv);
    if (!args) return 3;

    // Handle non-analysis commands
    if (args->command == Command::Help) {
        printUsage(argv[0]);
        return 0;
    }

    if (args->command == Command::Version) {
        std::printf("IccTest v%s\n", kVersion);
        return 0;
    }

    // Configure logging
    auto& logger = Logger::instance();
    if (args->verbose) {
        logger.setLevel(LogLevel::kTrace);
    } else if (args->quiet) {
        logger.setLevel(LogLevel::kError);
    } else {
        logger.setLevel(LogLevel::kWarn);
    }

    // Create formatter
    std::unique_ptr<OutputFormatter> formatter;
    switch (args->format) {
        case OutputFormat::Json:  formatter = createJsonFormatter(); break;
        case OutputFormat::Sarif: formatter = createSarifFormatter(); break;
        case OutputFormat::Text:
        default:
            formatter = createTextFormatter();
            break;
        // Xml, Pawg, Csv: not yet implemented — fall back to text
        case OutputFormat::Xml:
        case OutputFormat::Pawg:
        case OutputFormat::Csv:
            ICCTEST_WARN("Output format not yet implemented, falling back to text");
            formatter = createTextFormatter();
            break;
    }

    // Handle registry command
    if (args->command == Command::Registry) {
        auto jfmt = createJsonFormatter();
        jfmt->formatRegistry(std::cout);
        return 0;
    }

    // Build analysis options
    AnalysisOptions opts;
    opts.minSeverity  = args->minSeverity;
    opts.maxFindings  = args->maxFindings;
    opts.ubPreScan = true;

    // Set up output stream (file or stdout)
    std::ofstream fileOut;
    std::ostream* outStream = &std::cout;
    if (!args->outputPath.empty()) {
        fileOut.open(args->outputPath);
        if (!fileOut.is_open()) {
            std::fprintf(stderr, "Error: cannot open output file '%s'\n",
                         args->outputPath.c_str());
            return 2;
        }
        outStream = &fileOut;
    }

    // Canonicalize input path (resolve relative paths)
    std::filesystem::path inputPath(args->inputPath);
    std::error_code ec;
    auto canonical = std::filesystem::canonical(inputPath, ec);
    if (ec) {
        std::fprintf(stderr, "Error: cannot resolve path '%s': %s\n",
                     args->inputPath.c_str(), ec.message().c_str());
        return 2;
    }
    std::string resolvedPath = canonical.string();

    // Run analysis
    IccTestRunner runner;
    FormatOptions fmtOpts;
    fmtOpts.useColor  = !args->noColor && args->outputPath.empty();
    fmtOpts.verbose   = args->verbose;
    fmtOpts.inputFile = resolvedPath;

    auto runAnalysis = [&]() -> AnalysisResult {
        return runner.analyze(resolvedPath, opts);
    };

    AnalysisResult result;

    if (args->sandbox && isSandboxAvailable()) {
        ICCTEST_DEBUG("Running analysis in sandbox");
        SandboxLimits limits;
        auto outcome = runSandboxed(runAnalysis, limits);

        if (auto* r = std::get_if<AnalysisResult>(&outcome)) {
            result = std::move(*r);
        } else {
            auto& err = std::get<SandboxError>(outcome);
            std::fprintf(stderr, "Sandbox error: %s\n", err.message.c_str());

            // Report the sandbox error as a finding
            result.findings.push_back(Finding{
                {CheckID::Kind::Heuristic, 0},
                Severity::CRITICAL,
                "Analysis terminated by sandbox: " + err.message,
                "", ""
            });
            result.stats.findingsTotal = 1;
            result.stats.findingsBySeverity[4] = 1;
        }
    } else {
        ICCTEST_DEBUG("Running analysis in-process (no sandbox)");
        try {
            result = runAnalysis();
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 2;
        }
    }

    // Format output
    formatter->format(result, fmtOpts, *outStream);

    // Exit code: 0 = no findings, 1 = findings detected
    return result.hasCritical() ? 1 :
           (result.stats.findingsTotal > 0 ? 1 : 0);
}
