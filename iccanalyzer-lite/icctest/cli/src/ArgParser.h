/*
 * IccTest CLI — ArgParser.h
 * Command-line argument parsing with V1-compatible interface.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#ifndef ICCTEST_ARGPARSER_H
#define ICCTEST_ARGPARSER_H

#include <icctest/CheckResult.h>

#include <string>
#include <vector>
#include <optional>

namespace icctest {

/// Output format for the CLI tool.
enum class OutputFormat : uint8_t {
    Text,    // Colored terminal output (default)
    Json,    // Structured JSON
    Sarif,   // SARIF 2.1.0 (for CI integration)
    Xml,     // Per-finding XML with XSLT
    Pawg,    // ICC PAWG assessment report
    Csv,     // Batch processing output
};

/// Command to execute (determines primary behavior).
enum class Command : uint8_t {
    Analyze,      // Full analysis (default)
    Registry,     // Dump check registry
    Version,      // Print version
    Help,         // Print usage
};

/// Parsed command-line arguments.
struct ParsedArgs {
    Command     command  = Command::Analyze;
    OutputFormat format  = OutputFormat::Text;

    std::string inputPath;         // Profile to analyze
    std::string outputPath;        // Output file (empty = stdout)

    Severity    minSeverity = Severity::INFO;
    bool        noColor     = false;
    bool        verbose     = false;
    bool        quiet       = false;
    bool        sandbox     = true;   // Enable Linux sandbox (default on)
    bool        noFix       = false;  // V1 -nf compatibility

    std::vector<CheckPhase> phases;   // Empty = all
    int         maxFindings = 0;
};

/// Parse argc/argv into ParsedArgs.
/// Returns nullopt on parse error (error message printed to stderr).
std::optional<ParsedArgs> parseArgs(int argc, char** argv);

/// Print usage message to stderr.
void printUsage(const char* progName);

} // namespace icctest

#endif // ICCTEST_ARGPARSER_H
