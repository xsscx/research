/**
 * @name Integer overflow in multiplication
 * @description Detects multiplication operations that may overflow
 * @kind problem
 * @problem.severity warning
 * @id cpp/integer-overflow-multiply
 * @tags security
 *       correctness
 */

import cpp

predicate isClutSizeCalculation(MulExpr mul) {
  mul.getFile().toString().matches("%iccAnalyzer.cpp") and
  exists(Variable v |
    v.getName().matches("%clutSize%") or
    v.getName().matches("%totalEntries%")
  )
}

from MulExpr mul
where isClutSizeCalculation(mul)
  and not exists(IfStmt guard |
    guard.getCondition().getAChild*().(RelationalOperation).getAnOperand().toString().matches("%UINT32_MAX%") and
    guard.getLocation().getStartLine() < mul.getLocation().getStartLine() and
    guard.getLocation().getStartLine() > mul.getLocation().getStartLine() - 10
  )
select mul, "Multiplication may overflow without overflow check"
