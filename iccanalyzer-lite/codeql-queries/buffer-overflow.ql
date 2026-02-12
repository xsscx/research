/**
 * @name Buffer Overflow Detection
 * @description Finds potential buffer overflow vulnerabilities in ICC profile parsing
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-buffer-overflow
 * @tags security
 *       memory-safety
 *       buffer-overflow
 *       exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.security.BufferWrite

/**
 * Module for tracking taint from file I/O to buffer operations
 */
module FileToBufferConfigModule implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall fc |
      fc = source.asExpr() and
      (
        fc.getTarget().getName().matches("%Read%") or
        fc.getTarget().getName().matches("%read%") or
        fc.getTarget().getName().matches("%fread%") or
        fc.getTarget().getName().matches("%Load%")
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ArrayExpr ae | ae.getArrayOffset() = sink.asExpr())
    or
    exists(FunctionCall fc |
      fc.getTarget().getName() in ["memcpy", "strcpy", "strncpy", "sprintf", "snprintf"] and
      fc.getAnArgument() = sink.asExpr()
    )
  }
}

module FileToBufferConfig = TaintTracking::Global<FileToBufferConfigModule>;

/**
 * Array access without bounds checking
 */
class UncheckedArrayAccess extends ArrayExpr {
  UncheckedArrayAccess() {
    // Array offset comes from potentially tainted source
    exists(DataFlow::Node source, DataFlow::Node sink |
      FileToBufferConfig::flow(source, sink) and
      sink.asExpr() = this.getArrayOffset()
    ) and
    // No bounds check before access (direct or compound)
    not exists(IfStmt guard, RelationalOperation cmp |
      guard.getCondition().getAChild*() = cmp and
      (
        // Direct: if (offset < size)
        cmp.getAnOperand() = this.getArrayOffset() or
        // Compound: if (base + offset < size) — covers offset + j < fileSize patterns
        exists(Expr compound |
          cmp.getAnOperand() = compound and
          compound.getAChild*() = this.getArrayOffset()
        )
      ) and
      guard.getThen().getAChild*() = this
    ) and
    // Not inside a for/while loop with a bounds-checking condition
    not exists(Loop loop, RelationalOperation cmp |
      loop.getCondition().getAChild*() = cmp and
      (
        cmp.getAnOperand().getAChild*() = this.getArrayOffset() or
        cmp.getAnOperand() = this.getArrayOffset()
      ) and
      loop.getStmt().getAChild*() = this
    )
  }
}

/**
 * Memory copy with untrusted size
 */
class UntrustedMemoryCopy extends FunctionCall {
  UntrustedMemoryCopy() {
    this.getTarget().getName() in ["memcpy", "memmove", "memset"] and
    exists(DataFlow::Node source, DataFlow::Node sink |
      FileToBufferConfig::flow(source, sink) and
      sink.asExpr() = this.getArgument(2) // size argument
    )
  }
}

/**
 * Allocation with untrusted size (heap overflow candidate)
 */
class UntrustedAllocation extends FunctionCall {
  UntrustedAllocation() {
    this.getTarget().getName() in ["malloc", "calloc", "realloc", "new"] and
    exists(DataFlow::Node source, DataFlow::Node sink |
      FileToBufferConfig::flow(source, sink) and
      (
        sink.asExpr() = this.getArgument(0) or // malloc size
        sink.asExpr() = this.getArgument(1) // calloc size
      )
    )
  }
}

from UncheckedArrayAccess access, string message
where
  message =
    "Potential buffer overflow: Array access with untrusted offset from file I/O. " +
      "Offset value originates from Read/Load operation without bounds validation."
select access, message
