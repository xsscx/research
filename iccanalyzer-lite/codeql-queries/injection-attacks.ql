/**
 * @name HTML, JavaScript, and Code Injection Vulnerabilities
 * @description Detects injection vulnerabilities including XSS (HTML/JavaScript injection),
 *              SQL injection, command injection, path traversal, format string bugs, and
 *              other code injection attacks in ICC profile processing tools.
 * @kind problem
 * @problem.severity error
 * @id icc/injection-attacks
 * @tags security xss injection sql-injection command-injection path-traversal exploit-research
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

/**
 * HTML output functions (potential XSS sinks)
 */
class HtmlOutputFunction extends Function {
  HtmlOutputFunction() {
    this.getName().matches([
      "fprintf", "printf", "sprintf", "snprintf",
      "write", "fwrite", "puts", "fputs",
      "cout%",  // C++ streams
      "operator<<",  // Stream operators
      "%ToHtml%", "%toHtml%",  // Custom HTML generation
      "%WriteHtml%", "%writeHtml%"
    ])
  }
}

/**
 * HTML/JavaScript injection (XSS)
 */
class HtmlInjection extends FunctionCall {
  HtmlInjection() {
    this.getTarget() instanceof HtmlOutputFunction and
    // Output contains user-controlled data
    exists(VariableAccess va |
      this.getAnArgument() = va and
      // Not sanitized with HTML encoding
      not exists(FunctionCall sanitize |
        sanitize.getTarget().getName().matches([
          "%htmlEncode%", "%htmlEscape%",
          "%escapeHtml%", "%sanitize%"
        ]) and
        sanitize.getAnArgument() = va
      )
    )
  }
  
  string getInjectionContext() {
    if this.getTarget().getName().matches("%Html%") then
      result = "Direct HTML output"
    else if this.getTarget().getName().matches(["%printf%", "%fprintf%"]) then
      result = "Format string to HTML"
    else
      result = "Potential HTML context"
  }
}

/**
 * SQL query construction (SQL injection)
 */
class SqlQueryConstruction extends FunctionCall {
  SqlQueryConstruction() {
    // SQL execution functions
    this.getTarget().getName().matches([
      "sqlite3_exec",
      "mysql_query", "mysql_real_query",
      "PQexec", "PQexecParams",  // PostgreSQL
      "exec", "execute"  // Generic
    ])
  }
  
  predicate usesParameterizedQuery() {
    // Check for prepared statements or parameterized queries
    this.getTarget().getName().matches([
      "%prepare%", "%bind%",
      "sqlite3_prepare%", "PQexecParams"
    ])
  }
}

/**
 * Command execution functions (command injection)
 */
class CommandExecutionFunction extends Function {
  CommandExecutionFunction() {
    this.getName().matches([
      "system", "popen", "exec%",
      "execl", "execlp", "execle", "execv", "execvp", "execve",
      "fork", "ShellExecute%",
      "CreateProcess%",
      "WinExec"
    ])
  }
}

/**
 * Command injection vulnerability
 */
class CommandInjection extends FunctionCall {
  CommandInjection() {
    this.getTarget() instanceof CommandExecutionFunction and
    // Command contains user-controlled data
    exists(VariableAccess va |
      this.getAnArgument() = va and
      // Not properly quoted/escaped
      not exists(FunctionCall escape |
        escape.getTarget().getName().matches([
          "%shellEscape%", "%quotemeta%", "%escapeshellcmd%"
        ]) and
        escape.getAnArgument() = va
      )
    )
  }
  
  string getCommandType() {
    if this.getTarget().getName() = "system" then
      result = "System shell command"
    else if this.getTarget().getName().matches("exec%") then
      result = "Direct execution"
    else if this.getTarget().getName() = "popen" then
      result = "Pipe to command"
    else
      result = "Process creation"
  }
}

/**
 * Path manipulation functions (path traversal risk)
 */
class PathManipulationFunction extends Function {
  PathManipulationFunction() {
    this.getName().matches([
      "fopen", "open", "openat",
      "freopen", "fdopen",
      "remove", "unlink", "rmdir",
      "chmod", "chown",
      "stat", "lstat", "access",
      "readlink", "realpath"
    ])
  }
}

/**
 * Path traversal vulnerability
 */
class PathTraversal extends FunctionCall {
  PathTraversal() {
    this.getTarget() instanceof PathManipulationFunction and
    // Path contains user input
    exists(VariableAccess va |
      this.getArgument(0) = va and
      va.getTarget().getName().matches([
        "%path%", "%file%", "%filename%", "%dir%", "%name%"
      ]) and
      // Not validated against path traversal
      not exists(FunctionCall validate |
        validate.getTarget().getName().matches([
          "%validatePath%", "%canonicalize%", "%realpath%",
          "%normalizePath%", "%checkPath%"
        ]) and
        validate.getAnArgument() = va
      )
    )
  }
  
  predicate hasTraversalPattern() {
    // Check for literal path traversal patterns
    this.getAnArgument().toString().matches("%../%")
    or this.getAnArgument().toString().matches("%..//%")
  }
}

/**
 * Format string vulnerabilities
 */
class FormatStringVulnerability extends FunctionCall {
  FormatStringVulnerability() {
    this.getTarget().getName().matches([
      "printf", "fprintf", "sprintf", "snprintf",
      "vprintf", "vfprintf", "vsprintf", "vsnprintf",
      "syslog", "err", "warn"
    ]) and
    // Format string is user-controlled (not a literal)
    exists(VariableAccess va |
      va = this.getArgument(0) or  // printf family: format is first arg
      va = this.getArgument(1)     // fprintf family: format is second arg
    )
  }
  
  string getSeverity() {
    if this.getTarget().getName().matches("sprintf%") then
      result = "Critical (no bounds checking)"
    else if this.getTarget().getName().matches("snprintf%") then
      result = "High (bounded but still exploitable)"
    else
      result = "High (arbitrary read/write)"
  }
}

/**
 * LDAP injection
 */
class LdapInjection extends FunctionCall {
  LdapInjection() {
    this.getTarget().getName().matches([
      "ldap_search%", "ldap_add%", "ldap_modify%", "ldap_delete%"
    ]) and
    // Filter/DN contains user input without escaping
    exists(VariableAccess va |
      this.getAnArgument() = va and
      not exists(FunctionCall escape |
        escape.getTarget().getName().matches("%ldap%escape%") and
        escape.getAnArgument() = va
      )
    )
  }
}

/**
 * Log injection (log forging)
 */
class LogInjection extends FunctionCall {
  LogInjection() {
    this.getTarget().getName().matches([
      "syslog", "fprintf%", "printf",
      "%log%", "%Log%"
    ]) and
    exists(VariableAccess va |
      this.getAnArgument() = va and
      // Contains newlines or ANSI codes that could forge log entries
      va.getTarget().getName().matches([
        "%message%", "%msg%", "%text%", "%data%"
      ])
    )
  }
}

/**
 * Regular expression injection (ReDoS)
 */
class RegexInjection extends FunctionCall {
  RegexInjection() {
    this.getTarget().getName().matches([
      "regcomp", "regexec",
      "std::regex%",
      "pcre_%"
    ]) and
    // Regex pattern is user-controlled
    exists(VariableAccess va |
      this.getArgument(0) = va or
      this.getArgument(1) = va
    )
  }
}

/**
 * Eval-like functions (code injection)
 */
class EvalFunction extends Function {
  EvalFunction() {
    this.getName().matches([
      "eval", "exec",
      "PyRun_String", "Py_CompileString",  // Python embedding
      "luaL_dostring", "luaL_loadstring",  // Lua embedding
      "dlopen", "dlsym"  // Dynamic loading
    ])
  }
}

/**
 * Code injection via eval
 */
class CodeInjection extends FunctionCall {
  CodeInjection() {
    this.getTarget() instanceof EvalFunction and
    exists(VariableAccess va |
      this.getAnArgument() = va
    )
  }
}

/**
 * Template injection
 */
class TemplateInjection extends FunctionCall {
  TemplateInjection() {
    this.getTarget().getName().matches([
      "%render%", "%template%", "%expand%"
    ]) and
    exists(VariableAccess va |
      this.getAnArgument() = va and
      va.getTarget().getName().matches([
        "%template%", "%tmpl%", "%pattern%"
      ])
    )
  }
}

/**
 * Header injection (HTTP response splitting)
 */
class HeaderInjection extends FunctionCall {
  HeaderInjection() {
    (
      // CGI header output
      this.getTarget().getName().matches([
        "printf", "fprintf", "puts", "fputs"
      ]) and
      this.getAnArgument().toString().matches([
        "%Content-Type%", "%Location%", "%Set-Cookie%",
        "%HTTP/%", "%\r\n%", "%\n%"
      ])
    ) and
    // Contains user input
    exists(VariableAccess va |
      this.getAnArgument() = va and
      // Not validated for newlines
      not exists(FunctionCall validate |
        validate.getTarget().getName().matches([
          "%stripCRLF%", "%removeNewlines%", "%sanitizeHeader%"
        ]) and
        validate.getAnArgument() = va
      )
    )
  }
}

/**
 * Unsafe deserialization (separate from XML)
 */
class UnsafeDeserialization extends FunctionCall {
  UnsafeDeserialization() {
    this.getTarget().getName().matches([
      "unserialize", "pickle.loads",
      "yaml.load",  // unsafe YAML
      "json_decode",  // if not validated
      "readObject"
    ]) and
    // Data comes from untrusted source
    exists(VariableAccess va |
      this.getAnArgument() = va and
      va.getTarget().getName().matches([
        "%input%", "%data%", "%request%", "%post%", "%get%"
      ])
    )
  }
}

/**
 * String manipulation without bounds checking
 */
class UnsafeStringOperation extends FunctionCall {
  UnsafeStringOperation() {
    this.getTarget().getName().matches([
      "strcpy", "strcat", "gets",
      "sprintf"  // No bounds checking
    ])
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
  (
    // Category 1: HTML/JavaScript Injection (XSS)
    exists(HtmlInjection xss |
      location = xss and
      message = "[XSS] HTML/JavaScript injection: " + xss.getTarget().getName() + 
                " with unsanitized user input (" + xss.getInjectionContext() + "). " +
                "Use HTML encoding (htmlspecialchars, xmlEncodeSpecialChars)."
    )
    or
    // Category 2: SQL Injection
    exists(SqlQueryConstruction sql |
      location = sql and
      not sql.usesParameterizedQuery() and
      message = "[SQL Injection] SQL query construction without parameterization: " + 
                sql.getTarget().getName() + ". " +
                "Use prepared statements or parameterized queries."
    )
    or
    // Category 3: Command Injection
    exists(CommandInjection cmd |
      location = cmd and
      message = "[Command Injection] Command execution with unescaped user input: " + 
                cmd.getTarget().getName() + " (" + cmd.getCommandType() + "). " +
                "Validate/escape input or use exec() family with separate arguments."
    )
    or
    // Category 4: Path Traversal
    exists(PathTraversal path |
      location = path and
      message = "[Path Traversal] File operation with unvalidated path: " + 
                path.getTarget().getName() + ". " +
                "Validate path with realpath() or check for '../' patterns."
    )
    or
    // Category 5: Format String Vulnerability
    exists(FormatStringVulnerability fmt |
      location = fmt and
      message = "[Format String] User-controlled format string in " + 
                fmt.getTarget().getName() + ". " +
                "Severity: " + fmt.getSeverity() + ". Use literal format strings only."
    )
    or
    // Category 6: LDAP Injection
    exists(LdapInjection ldap |
      location = ldap and
      message = "[LDAP Injection] LDAP operation with unescaped user input: " + 
                ldap.getTarget().getName() + ". " +
                "Use LDAP escaping functions for DN and filter."
    )
    or
    // Category 7: Log Injection
    exists(LogInjection log |
      location = log and
      message = "[Log Injection] Log output with unsanitized user input: " + 
                log.getTarget().getName() + ". " +
                "Strip newlines and ANSI codes to prevent log forging."
    )
    or
    // Category 8: Regex Injection (ReDoS)
    exists(RegexInjection regex |
      location = regex and
      message = "[Regex Injection] Regular expression with user-controlled pattern: " + 
                regex.getTarget().getName() + ". " +
                "Potential ReDoS (catastrophic backtracking). Validate pattern complexity."
    )
    or
    // Category 9: Code Injection
    exists(CodeInjection code |
      location = code and
      message = "[Code Injection] Dynamic code execution: " + 
                code.getTarget().getName() + " with user-controlled input. " +
                "Never execute user-provided code. Use safe alternatives."
    )
    or
    // Category 10: Template Injection
    exists(TemplateInjection tmpl |
      location = tmpl and
      message = "[Template Injection] Template rendering with user-controlled template: " + 
                tmpl.getTarget().getName() + ". " +
                "Use sandboxed template engine or validate template syntax."
    )
    or
    // Category 11: Header Injection (HTTP Response Splitting)
    exists(HeaderInjection header |
      location = header and
      message = "[Header Injection] HTTP header with user input containing CRLF: " + 
                header.getTarget().getName() + ". " +
                "Strip CR/LF characters to prevent response splitting."
    )
    or
    // Category 12: Unsafe Deserialization
    exists(UnsafeDeserialization deser |
      location = deser and
      message = "[Unsafe Deserialization] Deserialization of untrusted data: " + 
                deser.getTarget().getName() + ". " +
                "Validate data integrity (HMAC) or use safe serialization formats (JSON)."
    )
    or
    // Category 13: Unsafe String Operations
    exists(UnsafeStringOperation unsafe |
      location = unsafe and
      message = "[Buffer Overflow] Unsafe string operation: " + 
                unsafe.getTarget().getName() + " without bounds checking. " +
                "Replace with " + unsafe.getReplacement() + "."
    )
  )
select location, message
