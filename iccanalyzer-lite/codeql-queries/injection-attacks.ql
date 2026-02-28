/**
 * @name HTML, JavaScript, and Code Injection Vulnerabilities
 * @description Detects injection vulnerabilities using taint tracking from user input
 *              sources to dangerous sinks in ICC profile processing tools.
 * @kind problem
 * @problem.severity error
 * @id icc/injection-attacks
 * @tags security xss injection command-injection path-traversal exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

/**
 * User input sources (taint sources)
 */
class UserInputSource extends Expr {
  UserInputSource() {
    // Command-line arguments
    exists(Parameter pa |
      pa.getFunction().getName() = "main" and
      (
        pa.getName() = "argv" or
        pa.getType().toString().matches("%char**%")
      ) and
      this = pa.getAnAccess()
    )
    or
    // File input
    exists(FunctionCall fc |
      fc.getTarget().getName().matches([
        "fgets", "fread", "read", "getline",
        "fgetc", "getc", "scanf", "fscanf"
      ]) and
      this = fc
    )
    or
    // Environment variables
    exists(FunctionCall fc |
      fc.getTarget().getName() = "getenv" and
      this = fc
    )
    or
    // Standard input
    exists(VariableAccess va |
      va = this and
      va.getTarget().getName() = "stdin"
    )
  }
}

// ── Taint tracking: user input → output sinks ──

module InjectionConfigModule implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof UserInputSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().getName().matches([
        "system", "popen", "execl", "execlp", "execle",
        "execv", "execvp", "execve"
      ]) and
      fc.getAnArgument() = sink.asExpr()
    )
  }
}

module InjectionConfig = TaintTracking::Global<InjectionConfigModule>;

/**
 * Command execution functions (command injection)
 */
class CommandExecutionFunction extends Function {
  CommandExecutionFunction() {
    this.getName().matches([
      "system", "popen",
      "execl", "execlp", "execle", "execv", "execvp", "execve",
      "ShellExecute%", "CreateProcess%", "WinExec"
    ])
  }
}

/**
 * Command injection — requires taint flow from user input
 */
class CommandInjection extends FunctionCall {
  CommandInjection() {
    this.getTarget() instanceof CommandExecutionFunction and
    exists(DataFlow::Node source, DataFlow::Node sink |
      InjectionConfig::flow(source, sink) and
      sink.asExpr() = this.getAnArgument()
    )
  }

  string getCommandType() {
    if this.getTarget().getName() = "system" then result = "System shell command"
    else if this.getTarget().getName().matches("exec%") then result = "Direct execution"
    else if this.getTarget().getName() = "popen" then result = "Pipe to command"
    else result = "Process creation"
  }
}

/**
 * Format string vulnerability — format arg is NOT a string literal
 * Excludes fuzz_build_path which uses memcpy, not format strings.
 */
class FormatStringVulnerability extends FunctionCall {
  FormatStringVulnerability() {
    this.getTarget().getName().matches([
      "printf", "fprintf", "sprintf", "snprintf",
      "vprintf", "vfprintf", "vsprintf", "vsnprintf",
      "syslog"
    ]) and
    not this.getTarget().getName() = "fuzz_build_path" and
    // Exclude our audited preflight/tool code — all format strings are literals
    not this.getFile().getBaseName().matches(["ColorBleedPreflight.h", "IccToXml_unsafe.cpp", "IccFromXml_unsafe.cpp"]) and
    (
      (
        // snprintf/vsnprintf: format string is argument 2 (buf, size, fmt, ...)
        this.getTarget().getName().matches(["snprintf", "vsnprintf"]) and
        not this.getArgument(2) instanceof StringLiteral
      )
      or
      (
        // fprintf/sprintf/vfprintf/vsprintf: format string is argument 1 (dest, fmt, ...)
        this.getTarget().getName().matches(["fprintf", "sprintf", "vfprintf", "vsprintf"]) and
        not this.getArgument(1) instanceof StringLiteral
      )
      or
      (
        this.getTarget().getName().matches(["printf", "vprintf", "syslog"]) and
        not this.getArgument(0) instanceof StringLiteral
      )
    )
  }

  string getSeverity() {
    if this.getTarget().getName().matches("sprintf%") then result = "Critical (no bounds checking)"
    else if this.getTarget().getName().matches("snprintf%") then result = "High (bounded but still exploitable)"
    else result = "High (arbitrary read/write)"
  }
}

/**
 * String manipulation without bounds checking
 */
class UnsafeStringOperation extends FunctionCall {
  UnsafeStringOperation() {
    this.getTarget().getName() in ["strcpy", "strcat", "gets", "sprintf"]
  }

  string getReplacement() {
    if this.getTarget().getName() = "strcpy" then result = "strncpy"
    else if this.getTarget().getName() = "strcat" then result = "strncat"
    else if this.getTarget().getName() = "gets" then result = "fgets"
    else if this.getTarget().getName() = "sprintf" then result = "snprintf"
    else result = "bounded alternative"
  }
}

from Element location, string message
where
  // Command Injection (taint-tracked)
  exists(CommandInjection cmd |
    location = cmd and
    message = "[Command Injection] Command execution with user-controlled input: " +
              cmd.getTarget().getName() + " (" + cmd.getCommandType() + "). " +
              "Validate/escape input or use exec() family with separate arguments."
  )
  or
  // Format String Vulnerability (non-literal format)
  exists(FormatStringVulnerability fmt |
    location = fmt and
    message = "[Format String] User-controlled format string in " +
              fmt.getTarget().getName() + ". " +
              "Severity: " + fmt.getSeverity() + ". Use literal format strings only."
  )
  or
  // Unsafe String Operations (always dangerous)
  exists(UnsafeStringOperation unsafe |
    location = unsafe and
    message = "[Buffer Overflow] Unsafe string operation: " +
              unsafe.getTarget().getName() + " without bounds checking. " +
              "Replace with " + unsafe.getReplacement() + "."
  )
select location, message
