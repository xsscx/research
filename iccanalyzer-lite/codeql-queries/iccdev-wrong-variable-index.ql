/**
 * @name Loop uses wrong index variable for array access
 * @description Detects patterns where a for-loop iterates with one index
 *              variable but array subscript expressions inside the loop use
 *              a different index variable from an outer scope. This causes
 *              incorrect data access or OOB reads.
 *              This is the exact pattern fixed by CFL-052 (fromIt8 used
 *              nValueIdx instead of nSrcIndex for sample access).
 * @kind problem
 * @id icc/wrong-variable-index
 * @problem.severity error
 * @security-severity 7.0
 * @precision low
 * @tags security
 *       external/cwe/cwe-787
 *       external/cwe/cwe-125
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A function in ICC code that processes indexed data.
 */
class IccDataFunction extends Function {
  IccDataFunction() {
    exists(File f | f = this.getFile() |
      f.getBaseName().matches("Icc%") or
      f.getBaseName().matches("icc%")
    )
  }
}

from ForStmt innerLoop, ForStmt outerLoop, ArrayExpr ae, Variable outerVar, Variable innerVar
where
  innerLoop.getEnclosingFunction() instanceof IccDataFunction and
  // Nested loops
  innerLoop.getParentStmt+() = outerLoop and
  // Outer loop variable
  outerVar = outerLoop.getAnIterationVariable() and
  // Inner loop variable
  innerVar = innerLoop.getAnIterationVariable() and
  outerVar != innerVar and
  // Focus on data-bearing arrays/fields rather than simple lookup tables.
  not ae.getArrayBase() instanceof VariableAccess and
  // Array access inside inner loop uses outer loop variable
  ae.getEnclosingStmt().getParentStmt*() = innerLoop.getStmt() and
  ae.getArrayOffset().(VariableAccess).getTarget() = outerVar and
  // Diagnostic/logging lookups often intentionally use the outer index.
  not exists(FunctionCall fc | fc.getAnArgument() = ae) and
  // The array is not also indexed by the inner var elsewhere in the same expression
  not exists(ArrayExpr ae2 |
    ae2.getEnclosingStmt() = ae.getEnclosingStmt() and
    ae2.getArrayOffset().(VariableAccess).getTarget() = innerVar and
    ae2.getArrayBase().(VariableAccess).getTarget() = ae.getArrayBase().(VariableAccess).getTarget()
  )
select ae,
  "Array access in inner loop of " + innerLoop.getEnclosingFunction().getName() +
    " uses outer loop variable '" + outerVar.getName() +
    "' instead of inner loop variable '" + innerVar.getName() +
    "' — possible wrong-index bug (CWE-787, CFL-052 pattern)"
