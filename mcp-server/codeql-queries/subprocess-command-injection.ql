/**
 * @name Subprocess command injection via unsanitized user input
 * @description Detects user-controlled input flowing to subprocess calls without
 *              passing through _sanitize_cmake_args or _resolve_build_dir first.
 *              The MCP server accepts build_dir, extra_cmake_args, target, and
 *              other params from untrusted MCP/REST clients.
 * @kind path-problem
 * @problem.severity error
 * @id icc-mcp/subprocess-command-injection
 * @tags security command-injection subprocess mcp
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * A source of user input from MCP tool function parameters.
 * These are the async def tool functions that receive untrusted input.
 */
class McpToolParameter extends DataFlow::Node {
  McpToolParameter() {
    exists(Function f, Parameter p |
      f.getName() in [
        "cmake_configure", "cmake_build",
        "create_all_profiles", "run_iccdev_tests"
      ] and
      p = f.getArg(_) and
      p.getName() in [
        "build_dir", "extra_cmake_args", "target",
        "build_type", "sanitizers", "compiler", "generator"
      ] and
      this.asExpr() = p.getAUse()
    )
  }
}

/**
 * A source of user input from web_ui.py request body parsing.
 */
class WebUiRequestInput extends DataFlow::Node {
  WebUiRequestInput() {
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      this.asExpr() = c
    )
  }
}

/**
 * A sink where subprocess is invoked.
 */
class SubprocessSink extends DataFlow::Node {
  SubprocessSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "create_subprocess_exec" or
        c.getFunc().(Attribute).getName() = "run" or
        c.getFunc().(Attribute).getName() = "Popen" or
        c.getFunc().(Attribute).getName() = "call" or
        c.getFunc().(Attribute).getName() = "check_output"
      ) and
      this.asExpr() = c.getAnArg()
    )
  }
}

/**
 * A sanitizer that blocks tainted data.
 */
class InputSanitizer extends DataFlow::Node {
  InputSanitizer() {
    exists(Call c |
      c.getFunc().(Name).getId() in [
        "_sanitize_cmake_args", "_resolve_build_dir",
        "_validate_path", "_validate_build_dir",
        "_validate_choice", "_validate_extra_cmake_args"
      ] and
      this.asExpr() = c
    )
  }
}

module SubprocessInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameter
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SubprocessSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof InputSanitizer
  }
}

module SubprocessInjection = TaintTracking::Global<SubprocessInjectionConfig>;
import SubprocessInjection::PathGraph

from SubprocessInjection::PathNode source, SubprocessInjection::PathNode sink
where SubprocessInjection::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsanitized user input from $@ flows to subprocess call without validation.",
  source.getNode(), "MCP tool parameter"
