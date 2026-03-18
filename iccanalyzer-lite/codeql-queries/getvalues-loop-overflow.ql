/**
 * @name m_nSize loop in GetValues/Interpolate writing to DstVector parameter
 * @description Template numeric tag classes (CIccTagFixedNum, CIccTagNum) loop to m_nSize
 *              when writing to a caller-provided DstVector buffer. If m_nSize (file-controlled)
 *              exceeds the caller's buffer capacity (nVectorSize), a stack-buffer-overflow occurs.
 *              CFL-030 fixes 14 source-level loops across GetValues and Interpolate methods.
 * @kind problem
 * @id iccproflib/security-queries/getvalues-loop-overflow
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-121
 *       external/cwe/cwe-787
 */

import cpp

from ForStmt loop, Function f, FieldAccess fa
where
  fa = loop.getCondition().(LTExpr).getRightOperand()
  and fa.getTarget().getName() = "m_nSize"
  and f = loop.getEnclosingFunction()
  and (f.getName().matches("%GetValues%") or f.getName().matches("%Interpolate%"))
select loop, "SBO: " + f.getName() + " uses m_nSize (file-controlled) as loop bound writing to DstVector parameter in " + f.getDeclaringType().getName() + ". Fix: use nVectorSize as loop bound (CFL-030)."
