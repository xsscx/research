/**
 * @name Integer Overflow in Allocation
 * @description Finds integer overflows that could lead to heap corruption
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-integer-overflow-allocation
 * @tags security
 *       integer-overflow
 *       memory-safety
 *       exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

/**
 * An arithmetic operation that may overflow
 */
class OverflowableArithmetic extends BinaryArithmeticOperation {
  OverflowableArithmetic() {
    (this instanceof MulExpr or this instanceof AddExpr) and
    this.getType().getUnspecifiedType() instanceof IntegralType
  }
}

/**
 * Allocation with potentially overflowed size
 */
class OverflowableAllocation extends FunctionCall {
  OverflowableAllocation() {
    this.getTarget().getName() in ["malloc", "calloc", "realloc", "new", "new[]"] and
    exists(OverflowableArithmetic arith |
      (
        this.getArgument(0).getAChild*() = arith or // malloc(size)
        this.getArgument(1).getAChild*() = arith // calloc(n, size)
      ) and
      // No overflow check
      not exists(IfStmt guard, RelationalOperation cmp |
        guard.getCondition() = cmp and
        cmp.getAnOperand().getAChild*() = arith.getAnOperand() and
        guard.getThen().getAChild*() = this
      )
    )
  }

  OverflowableArithmetic getOverflowableExpr() { this.getAnArgument().getAChild*() = result }
}

/**
 * Module for tracking untrusted sizes
 */
module UntrustedSizeConfigModule implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall fc |
      fc = source.asExpr() and
      fc.getTarget().getName().matches("%Read%")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(OverflowableArithmetic arith | sink.asExpr() = arith.getAnOperand())
  }
}

module UntrustedSizeConfig = TaintTracking::Global<UntrustedSizeConfigModule>;

from OverflowableAllocation alloc, OverflowableArithmetic arith, string message
where
  arith = alloc.getOverflowableExpr() and
  exists(DataFlow::Node source, DataFlow::Node sink |
    UntrustedSizeConfig::flow(source, sink) and
    sink.asExpr() = arith.getAnOperand()
  ) and
  message =
    "Integer overflow in allocation: Size calculation '" + arith.toString() + "' " +
      "uses untrusted input and may overflow, leading to small allocation " +
      "followed by heap buffer overflow."
select alloc, message, arith, "Arithmetic operation: " + arith.toString()
