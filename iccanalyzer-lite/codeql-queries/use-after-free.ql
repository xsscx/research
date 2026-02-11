/**
 * @name Use-After-Free Detection
 * @description Finds potential use-after-free vulnerabilities using control flow analysis
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-use-after-free
 * @tags security
 *       memory-safety
 *       use-after-free
 *       exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
 * A delete or free operation
 */
class Deallocation extends Expr {
  Deallocation() {
    this instanceof DeleteExpr
    or
    this instanceof DeleteArrayExpr
    or
    exists(FunctionCall fc |
      fc = this and
      fc.getTarget().getName() in ["free", "delete"]
    )
  }

  Expr getDeallocatedExpr() {
    result = this.(DeleteExpr).getExpr() or
    result = this.(DeleteArrayExpr).getExpr() or
    result = this.(FunctionCall).getArgument(0)
  }
}

/**
 * Access to a variable that may have been freed — requires same basic block
 * or provable control flow path without reassignment or null check.
 */
class PotentialUseAfterFree extends VariableAccess {
  PotentialUseAfterFree() {
    exists(Deallocation dealloc, Variable v |
      v = this.getTarget() and
      dealloc.getDeallocatedExpr() = v.getAnAccess() and
      dealloc.getEnclosingFunction() = this.getEnclosingFunction() and
      // Must be in the same basic block (straight-line code, no branches)
      dealloc.getBasicBlock() = this.getBasicBlock() and
      dealloc.getLocation().getEndLine() < this.getLocation().getStartLine() and
      // No reassignment between dealloc and use
      not exists(AssignExpr assign |
        assign.getLValue() = v.getAnAccess() and
        assign.getBasicBlock() = this.getBasicBlock() and
        dealloc.getLocation().getEndLine() < assign.getLocation().getStartLine() and
        assign.getLocation().getEndLine() < this.getLocation().getStartLine()
      ) and
      // Not a null check (if (ptr) or if (ptr != NULL))
      not exists(IfStmt guard |
        guard.getCondition().getAChild*() = this
      ) and
      // Not setting to null
      not exists(AssignExpr nullAssign |
        nullAssign.getLValue() = this and
        nullAssign.getRValue().getValue() = "0"
      )
    )
  }

  Deallocation getDeallocation() {
    exists(Variable v |
      v = this.getTarget() and
      result.getDeallocatedExpr() = v.getAnAccess() and
      result.getBasicBlock() = this.getBasicBlock() and
      result.getLocation().getEndLine() < this.getLocation().getStartLine() and
      result.getEnclosingFunction() = this.getEnclosingFunction()
    )
  }
}

from PotentialUseAfterFree use, Deallocation dealloc, string message
where
  dealloc = use.getDeallocation() and
  message =
    "Use-after-free: Variable '" + use.getTarget().getName() + "' is accessed after being freed. " +
      "Deallocation at line " + dealloc.getLocation().getStartLine().toString() + ", " +
      "use at line " + use.getLocation().getStartLine().toString() + "."
select use, message, dealloc, "Deallocation location"
