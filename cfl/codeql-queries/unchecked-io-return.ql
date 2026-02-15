/**
 * @name Unchecked return value from I/O function
 * @description Finds calls to fread/fwrite/fopen where return value is not checked.
 *              Excludes fclose (low-value: only fails on flush, not actionable in
 *              read paths, and checking it adds noise without security benefit).
 * @kind problem
 * @problem.severity error
 * @id cpp/unchecked-io-return
 * @tags security
 *       reliability
 */

import cpp

from FunctionCall fc
where fc.getTarget().getName() in ["fread", "fwrite", "fopen"]
  and not fc.getFile().toString().matches("%iccDEV%")
  and not exists(BinaryOperation cmp |
    cmp.getAnOperand() = fc or
    cmp.getAnOperand().(VariableAccess).getTarget().getAnAssignedValue() = fc
  )
  and not exists(IfStmt s | s.getCondition().getAChild*() = fc)
  and not exists(ReturnStmt s | s.getExpr().getAChild*() = fc)
  // Exclude if result assigned to a variable that is later checked in any
  // control structure (if/while/for), including patterns like if (!fp)
  and not exists(Variable v |
    v.getAnAssignedValue() = fc and
    exists(ControlStructure cs |
      cs.getControllingExpr().getAChild*().(VariableAccess).getTarget() = v
    )
  )
select fc, "Return value from " + fc.getTarget().getName() + " is not checked"
