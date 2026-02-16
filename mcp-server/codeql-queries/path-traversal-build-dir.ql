/**
 * @name Path traversal in build directory operations
 * @description Detects user-controlled build_dir values reaching file system
 *              operations (Path construction, open, mkdir) without passing
 *              through _resolve_build_dir or _validate_build_dir sanitizers.
 * @kind path-problem
 * @problem.severity error
 * @id icc-mcp/path-traversal-build-dir
 * @tags security path-traversal file-access mcp
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * User-supplied build_dir parameter in MCP tools and web handlers.
 */
class BuildDirSource extends DataFlow::Node {
  BuildDirSource() {
    exists(Function f, Name n |
      f.getName() in [
        "cmake_configure", "cmake_build",
        "create_all_profiles", "run_iccdev_tests",
        "cmake_option_matrix", "windows_build",
        "api_cmake_configure", "api_cmake_build",
        "api_create_profiles", "api_run_tests",
        "api_option_matrix", "api_windows_build"
      ] and
      n.getId() = "build_dir" and
      n.getScope() = f and
      this.asExpr() = n
    )
    or
    // body.get("build_dir") in web handlers
    exists(Call c, StringLiteral s |
      c.getFunc().(Attribute).getName() = "get" and
      s.getText() = "build_dir" and
      c.getAnArg() = s and
      this.asExpr() = c
    )
  }
}

/**
 * File system sinks: Path(), open(), mkdir, etc.
 */
class FileSystemSink extends DataFlow::Node {
  FileSystemSink() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "Path" or
        c.getFunc().(Name).getId() = "open" or
        c.getFunc().(Attribute).getName() in [
          "mkdir", "makedirs", "rmdir", "unlink", "rename",
          "is_file", "is_dir", "exists", "read_text", "write_text",
          "read_bytes", "write_bytes"
        ]
      ) and
      this.asExpr() = c.getAnArg()
    )
    or
    // Path / operator (division used for path joining)
    exists(BinaryExpr be |
      be.getOp() instanceof Div and
      this.asExpr() = be.getRight()
    )
  }
}

/**
 * Sanitizers that validate build_dir.
 * Includes calls to sanitizer functions AND the re.sub sanitization
 * inside _resolve_build_dir itself.
 */
class BuildDirSanitizer extends DataFlow::Node {
  BuildDirSanitizer() {
    exists(Call c |
      c.getFunc().(Name).getId() in [
        "_resolve_build_dir", "_validate_build_dir"
      ] and
      this.asExpr() = c
    )
    or
    // re.sub() inside _resolve_build_dir strips unsafe chars
    exists(Call c, Function f |
      f.getName() = "_resolve_build_dir" and
      c.getScope() = f and
      c.getFunc().(Attribute).getName() = "sub" and
      this.asExpr() = c
    )
  }
}

module PathTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof BuildDirSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof FileSystemSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof BuildDirSanitizer
  }
}

module PathTraversal = TaintTracking::Global<PathTraversalConfig>;
import PathTraversal::PathGraph

from PathTraversal::PathNode source, PathTraversal::PathNode sink
where PathTraversal::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled build_dir from $@ reaches file system operation without path validation.",
  source.getNode(), "build_dir parameter"
