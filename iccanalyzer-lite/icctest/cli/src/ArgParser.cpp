/*
 * IccTest CLI — ArgParser.cpp
 * Command-line argument parsing with V1-compatible interface.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * V1-compatible flags:
 *   -a <file>       Comprehensive analysis (text output)
 *   --json <file>   JSON output
 *   --report <file> Severity-sorted report (text)
 *   -xml <file> <out>  XML output with XSLT
 *   --registry      Dump check registry
 *   --pawg <file>   PAWG assessment report
 *   -nf <file>      No-fix mode (same as -a)
 *
 * New V2 flags:
 *   --sarif <file>  SARIF 2.1.0 output
 *   --csv <file>    CSV batch output
 *   --no-sandbox    Disable Linux sandbox
 *   --no-color      Disable terminal colors
 *   --min-severity <level>  Filter by minimum severity
 *   --max-findings <N>      Stop after N findings
 *   -v / --verbose  Verbose logging
 *   -q / --quiet    Suppress non-finding output
 *   -o <file>       Write output to file
 */

#include "ArgParser.h"

#include <cstdio>
#include <cstring>

namespace icctest {

void printUsage(const char* progName) {
    std::fprintf(stderr,
        "IccTest — ICC Profile Security & Conformance Analyzer v2.0\n"
        "Copyright (c) 1994 - 2026 David H Hoyt LLC\n"
        "\n"
        "Usage: %s [OPTIONS] <command> <file>\n"
        "\n"
        "Commands:\n"
        "  -a <file>           Comprehensive analysis (default)\n"
        "  --json <file>       JSON structured output\n"
        "  --sarif <file>      SARIF 2.1.0 output (CI integration)\n"
        "  --report <file>     Severity-sorted text report\n"
        "  -xml <file> <out>   XML with XSLT stylesheet\n"
        "  --pawg <file>       ICC PAWG assessment report\n"
        "  --csv <file>        CSV batch output\n"
        "  --registry          Dump check registry as JSON\n"
        "  -nf <file>          No-fix mode (same as -a)\n"
        "  --version           Print version\n"
        "  --help              Print this help\n"
        "\n"
        "Options:\n"
        "  --no-sandbox        Disable Linux sandbox\n"
        "  --no-color          Disable terminal colors\n"
        "  --min-severity <S>  Filter: INFO|LOW|MEDIUM|HIGH|CRITICAL\n"
        "  --max-findings <N>  Stop after N findings (0 = unlimited)\n"
        "  -o <file>           Write output to file\n"
        "  -v, --verbose       Verbose diagnostic logging\n"
        "  -q, --quiet         Suppress non-finding output\n"
        "\n"
        "Exit codes:\n"
        "  0  No findings\n"
        "  1  Findings detected\n"
        "  2  Error (bad input, missing file)\n"
        "  3  Usage error\n"
        "\n"
        "Examples:\n"
        "  %s -a profile.icc\n"
        "  %s --json profile.icc\n"
        "  %s --sarif profile.icc -o results.sarif\n"
        "  %s --registry\n"
        ,
        progName, progName, progName, progName, progName
    );
}

static Severity parseSeverity(const char* s) {
    if (std::strcmp(s, "INFO") == 0)     return Severity::INFO;
    if (std::strcmp(s, "LOW") == 0)      return Severity::LOW;
    if (std::strcmp(s, "MEDIUM") == 0)   return Severity::MEDIUM;
    if (std::strcmp(s, "HIGH") == 0)     return Severity::HIGH;
    if (std::strcmp(s, "CRITICAL") == 0) return Severity::CRITICAL;
    return Severity::INFO;
}

std::optional<ParsedArgs> parseArgs(int argc, char** argv) {
    if (argc < 2) {
        printUsage(argv[0]);
        return std::nullopt;
    }

    ParsedArgs args;
    int i = 1;

    while (i < argc) {
        const char* arg = argv[i];

        // Commands (set format + consume file argument)
        if (std::strcmp(arg, "-a") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Text;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: -a requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--json") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Json;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: --json requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--sarif") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Sarif;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: --sarif requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--report") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Text;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: --report requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "-xml") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Xml;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: -xml requires <file> <output>\n"); return std::nullopt; }
            if (++i < argc) args.outputPath = argv[i];
            else { std::fprintf(stderr, "Error: -xml requires <file> <output>\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--pawg") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Pawg;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: --pawg requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--csv") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Csv;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: --csv requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "-nf") == 0) {
            args.command = Command::Analyze;
            args.format = OutputFormat::Text;
            args.noFix = true;
            if (++i < argc) args.inputPath = argv[i];
            else { std::fprintf(stderr, "Error: -nf requires a file argument\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--registry") == 0) {
            args.command = Command::Registry;
        }
        else if (std::strcmp(arg, "--version") == 0) {
            args.command = Command::Version;
        }
        else if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
            args.command = Command::Help;
        }
        // Options
        else if (std::strcmp(arg, "--no-sandbox") == 0) {
            args.sandbox = false;
        }
        else if (std::strcmp(arg, "--no-color") == 0) {
            args.noColor = true;
        }
        else if (std::strcmp(arg, "--min-severity") == 0) {
            if (++i < argc) args.minSeverity = parseSeverity(argv[i]);
            else { std::fprintf(stderr, "Error: --min-severity requires a level\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "--max-findings") == 0) {
            if (++i < argc) args.maxFindings = std::atoi(argv[i]);
            else { std::fprintf(stderr, "Error: --max-findings requires a number\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "-o") == 0) {
            if (++i < argc) args.outputPath = argv[i];
            else { std::fprintf(stderr, "Error: -o requires a file path\n"); return std::nullopt; }
        }
        else if (std::strcmp(arg, "-v") == 0 || std::strcmp(arg, "--verbose") == 0) {
            args.verbose = true;
        }
        else if (std::strcmp(arg, "-q") == 0 || std::strcmp(arg, "--quiet") == 0) {
            args.quiet = true;
        }
        else if (arg[0] == '-') {
            std::fprintf(stderr, "Error: unknown option '%s'\n", arg);
            printUsage(argv[0]);
            return std::nullopt;
        }
        else {
            // Positional argument — treat as input file if not already set
            if (args.inputPath.empty()) {
                args.inputPath = arg;
            } else {
                std::fprintf(stderr, "Error: unexpected argument '%s'\n", arg);
                return std::nullopt;
            }
        }

        ++i;
    }

    // Validate: analyze commands need an input file
    if (args.command == Command::Analyze && args.inputPath.empty()) {
        std::fprintf(stderr, "Error: no input file specified\n");
        printUsage(argv[0]);
        return std::nullopt;
    }

    return args;
}

} // namespace icctest
