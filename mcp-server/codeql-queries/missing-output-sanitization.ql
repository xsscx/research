/**
 * @name Missing output sanitization on subprocess results
 * @description Detects subprocess output returned to MCP/REST clients without
 *              passing through _sanitize_output. Unsanitized output may contain
 *              ANSI escape sequences, control characters, or terminal injection.
 * @kind problem
 * @problem.severity warning
 * @id icc-mcp/missing-output-sanitization
 * @tags security sanitization output mcp
 */

import python

/**
 * Calls to subprocess that produce output (stdout/stderr).
 */
class SubprocessOutputCall extends Call {
  SubprocessOutputCall() {
    this.getFunc().(Attribute).getName() in [
      "create_subprocess_exec", "run", "check_output",
      "Popen", "communicate"
    ]
  }
}

/**
 * Calls to _sanitize_output that clean subprocess results.
 */
class SanitizeOutputCall extends Call {
  SanitizeOutputCall() {
    this.getFunc().(Name).getId() = "_sanitize_output"
  }
}

/**
 * Return statements in async tool functions.
 */
class ToolReturnStatement extends Return {
  Function enclosingTool;

  ToolReturnStatement() {
    enclosingTool = this.getScope() and
    enclosingTool.getName() in [
      "cmake_configure", "cmake_build",
      "create_all_profiles", "run_iccdev_tests",
      "inspect_profile", "analyze_security",
      "validate_roundtrip", "full_analysis",
      "profile_to_xml", "compare_profiles",
      "_run", "_run_build"
    ]
  }

  Function getToolFunction() { result = enclosingTool }
}

/**
 * Find _run and _run_build functions that already sanitize output.
 * These are the approved subprocess wrappers.
 */
class ApprovedSubprocessWrapper extends Function {
  ApprovedSubprocessWrapper() {
    this.getName() in ["_run", "_run_build"] and
    exists(SanitizeOutputCall sc | sc.getScope() = this)
  }
}

/**
 * Direct subprocess calls in tool functions (not through _run/_run_build).
 * These bypass the centralized sanitization.
 */
from SubprocessOutputCall subproc, Function tool
where
  tool = subproc.getScope() and
  tool.getName() in [
    "cmake_configure", "cmake_build",
    "create_all_profiles", "run_iccdev_tests",
    "inspect_profile", "analyze_security",
    "validate_roundtrip", "full_analysis",
    "profile_to_xml", "compare_profiles"
  ] and
  not exists(SanitizeOutputCall sc |
    sc.getScope() = tool and
    sc.getLocation().getStartLine() > subproc.getLocation().getStartLine()
  )
select subproc,
  "Direct subprocess call in " + tool.getName() +
  " bypasses _run/_run_build sanitization wrapper. " +
  "Use _run() or _run_build() instead, or add _sanitize_output() on the result."
