/**
 * @name SSRF/path traversal via REST API path parameter
 * @description Detects user-controlled `path` parameter from REST API requests
 *              flowing to file system operations or subprocess calls without
 *              passing through _validate_path. An attacker could use
 *              path=../../etc/passwd to read arbitrary files or trigger analysis
 *              on unintended targets.
 * @kind path-problem
 * @problem.severity error
 * @id icc-mcp/api-path-traversal
 * @tags security path-traversal ssrf rest-api
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * User-supplied `path` parameter from web_ui.py query string parsing.
 * Matches: request.query_params.get("path"), request.query_params["path"],
 *          body.get("path_a"), body.get("path_b")
 */
class ApiPathSource extends DataFlow::Node {
  ApiPathSource() {
    exists(Call c, StringLiteral s |
      c.getFunc().(Attribute).getName() = "get" and
      s.getText() in ["path", "path_a", "path_b", "directory"] and
      c.getAnArg() = s and
      this.asExpr() = c
    )
    or
    exists(Subscript sub, StringLiteral s |
      s.getText() in ["path", "path_a", "path_b", "directory"] and
      sub.getIndex() = s and
      this.asExpr() = sub
    )
  }
}

/**
 * File system and subprocess sinks that could be exploited.
 */
class FileOrProcessSink extends DataFlow::Node {
  FileOrProcessSink() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() in ["Path", "open"] or
        c.getFunc().(Attribute).getName() in [
          "create_subprocess_exec", "run", "read_text",
          "read_bytes", "exists", "is_file", "resolve"
        ]
      ) and
      this.asExpr() = c.getAnArg()
    )
    or
    // Path / operator for path joining
    exists(BinaryExpr be |
      be.getOp() instanceof Div and
      this.asExpr() = be.getRight()
    )
  }
}

/**
 * Sanitizers that validate paths against traversal.
 */
class PathSanitizer extends DataFlow::Node {
  PathSanitizer() {
    exists(Call c |
      c.getFunc().(Name).getId() in [
        "_validate_path", "_resolve_path", "_safe_resolve"
      ] and
      this.asExpr() = c
    )
    or
    // resolve().is_relative_to() pattern used inline
    exists(Call c |
      c.getFunc().(Attribute).getName() = "is_relative_to" and
      this.asExpr() = c
    )
  }
}

module ApiPathTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ApiPathSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOrProcessSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof PathSanitizer
  }
}

module ApiPathTraversal = TaintTracking::Global<ApiPathTraversalConfig>;
import ApiPathTraversal::PathGraph

from ApiPathTraversal::PathNode source, ApiPathTraversal::PathNode sink
where ApiPathTraversal::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled API path parameter from $@ reaches file/process operation without _validate_path.",
  source.getNode(), "REST API parameter"
