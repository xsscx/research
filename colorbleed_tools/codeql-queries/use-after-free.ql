/**
 * @name Use-After-Free Detection
 * @description Finds potential use-after-free vulnerabilities
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
 * Access to a variable that may have been freed
 */
class PotentialUseAfterFree extends VariableAccess {
  PotentialUseAfterFree() {
    exists(Deallocation dealloc, Variable v |
      v = this.getTarget() and
      dealloc.getDeallocatedExpr() = v.getAnAccess() and
      // Access happens after deallocation in control flow
      dealloc.getLocation().getEndLine() < this.getLocation().getStartLine() and
      dealloc.getEnclosingFunction() = this.getEnclosingFunction() and
      // No reassignment between dealloc and use
      not exists(AssignExpr assign |
        assign.getLValue() = v.getAnAccess() and
        dealloc.getLocation().getEndLine() < assign.getLocation().getStartLine() and
        assign.getLocation().getEndLine() < this.getLocation().getStartLine()
      )
    )
  }

  Deallocation getDeallocation() {
    exists(Variable v |
      v = this.getTarget() and
      result.getDeallocatedExpr() = v.getAnAccess() and
      result.getLocation().getEndLine() < this.getLocation().getStartLine() and
      result.getEnclosingFunction() = this.getEnclosingFunction()
    )
  }
}

/**
 * Double-free detection
 */
class DoubleFree extends Deallocation {
  DoubleFree() {
    exists(Deallocation first, Variable v |
      first.getDeallocatedExpr() = v.getAnAccess() and
      this.getDeallocatedExpr() = v.getAnAccess() and
      first != this and
      first.getLocation().getEndLine() < this.getLocation().getStartLine() and
      first.getEnclosingFunction() = this.getEnclosingFunction() and
      // No reassignment between frees
      not exists(AssignExpr assign |
        assign.getLValue() = v.getAnAccess() and
        first.getLocation().getEndLine() < assign.getLocation().getStartLine() and
        assign.getLocation().getEndLine() < this.getLocation().getStartLine()
      )
    )
  }

  Deallocation getFirstFree() {
    exists(Variable v |
      result.getDeallocatedExpr() = v.getAnAccess() and
      this.getDeallocatedExpr() = v.getAnAccess() and
      result != this and
      result.getLocation().getEndLine() < this.getLocation().getStartLine()
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
