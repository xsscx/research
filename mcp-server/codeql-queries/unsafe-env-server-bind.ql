/**
 * @name Unsafe environment variable use in server configuration
 * @description Detects environment variables (HOST, PORT) flowing to network
 *              bind operations (uvicorn.run, socket.bind) without validation.
 *              An attacker with env control could bind to 0.0.0.0 on unexpected
 *              ports, or inject non-numeric values causing crashes.
 * @kind path-problem
 * @problem.severity warning
 * @id icc-mcp/unsafe-env-server-bind
 * @tags security environment-variable server-configuration
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * os.environ.get() or os.getenv() calls for server-related variables.
 */
class EnvVarSource extends DataFlow::Node {
  EnvVarSource() {
    exists(Call c, StringLiteral s |
      (
        c.getFunc().(Attribute).getName() = "get" and
        c.getFunc().(Attribute).getObject().(Attribute).getName() = "environ"
      ) and
      s.getText() in ["HOST", "PORT", "BIND_ADDRESS"] and
      c.getAnArg() = s and
      this.asExpr() = c
    )
    or
    exists(Call c, StringLiteral s |
      c.getFunc().(Attribute).getName() = "getenv" and
      s.getText() in ["HOST", "PORT", "BIND_ADDRESS"] and
      c.getAnArg() = s and
      this.asExpr() = c
    )
  }
}

/**
 * Server bind sinks: uvicorn.run(), socket.bind(), etc.
 */
class ServerBindSink extends DataFlow::Node {
  ServerBindSink() {
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "run" or
        c.getFunc().(Attribute).getName() = "bind" or
        c.getFunc().(Attribute).getName() = "listen"
      ) and
      this.asExpr() = c.getAnArg()
    )
  }
}

/**
 * Validation functions that check env vars.
 */
class EnvValidation extends DataFlow::Node {
  EnvValidation() {
    exists(Call c |
      c.getFunc().(Name).getId() in [
        "int", "validate_port", "validate_host"
      ] and
      this.asExpr() = c
    )
  }
}

module EnvBindConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof EnvVarSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ServerBindSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof EnvValidation
  }
}

module EnvBind = TaintTracking::Global<EnvBindConfig>;
import EnvBind::PathGraph

from EnvBind::PathNode source, EnvBind::PathNode sink
where EnvBind::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Environment variable $@ flows to server bind without explicit validation.",
  source.getNode(), "env var"
