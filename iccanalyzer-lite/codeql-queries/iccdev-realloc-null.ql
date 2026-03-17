/**
 * @name icRealloc return value not checked for NULL
 * @description icRealloc() can return NULL on allocation failure.
 *              Using the result without a NULL check causes NULL pointer dereference.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id icc/realloc-null-check
 * @tags security
 *       reliability
 *       external/cwe/cwe-252
 *       external/cwe/cwe-476
 */
import cpp

from FunctionCall fc, Variable v
where
  fc.getTarget().getName() = "icRealloc" and
  exists(AssignExpr ae |
    ae.getRValue() = fc.getParent*() and
    ae.getLValue().(VariableAccess).getTarget() = v
  ) and
  not exists(IfStmt ifstmt |
    ifstmt.getCondition().getAChild*().(VariableAccess).getTarget() = v and
    ifstmt.getLocation().getStartLine() >= fc.getLocation().getStartLine() and
    ifstmt.getLocation().getStartLine() <= fc.getLocation().getStartLine() + 5
  )
select fc, "icRealloc() return value assigned to " + v.getName() + " without NULL check"
