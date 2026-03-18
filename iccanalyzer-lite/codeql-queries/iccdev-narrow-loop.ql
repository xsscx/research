/**
 * @name Narrow type compared with wide type in loop condition
 * @description Loop counter of type icUInt16Number compared to icUInt32Number bound
 *              can wrap around at 65535, causing infinite loop or missed elements.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id icc/narrow-loop-bound
 * @tags security
 *       reliability
 *       external/cwe/cwe-190
 *       external/cwe/cwe-835
 */
import cpp

from ForStmt fs, Variable counter, Variable bound
where
  exists(RelationalOperation cmp |
    cmp = fs.getCondition() or cmp = fs.getCondition().(BinaryLogicalOperation).getAnOperand() |
    cmp.getAnOperand().(VariableAccess).getTarget() = counter and
    cmp.getAnOperand().(VariableAccess).getTarget() = bound and
    counter != bound
  ) and
  counter.getType().getSize() < bound.getType().getSize() and
  counter.getType().getSize() <= 2 and
  bound.getType().getSize() >= 4 and
  // Exclude comparisons where the narrow variable is explicitly widened via static_cast
  not exists(RelationalOperation cmp2, Cast wideningCast |
    (cmp2 = fs.getCondition() or cmp2 = fs.getCondition().(BinaryLogicalOperation).getAnOperand()) and
    wideningCast = cmp2.getAnOperand() and
    wideningCast.getExpr().(VariableAccess).getTarget() = counter and
    wideningCast.getType().getSize() >= bound.getType().getSize()
  )
select fs, "Loop counter '" + counter.getName() + "' (" + counter.getType().toString() + ") compared with '" + bound.getName() + "' (" + bound.getType().toString() + ") — may wrap at " + (2.pow(counter.getType().getSize() * 8) - 1).toString()
