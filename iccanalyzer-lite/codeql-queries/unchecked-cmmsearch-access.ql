/**
 * @name Unchecked vector element access without size check
 * @description Accessing m_dst_to_mid[0] or m_weight[i] without checking
 *              if the vector is populated can cause out-of-bounds access
 *              when Begin() exits early or profiles fail to load.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id icc/unchecked-vector-access
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp

from ArrayExpr ae, string vecName
where
  vecName = ae.getArrayBase().(VariableAccess).getTarget().getName() and
  (
    vecName = "m_dst_to_mid" or
    vecName = "m_src_to_mid" or
    vecName = "m_weight"
  ) and
  // Not inside a size check
  not exists(IfStmt guard |
    guard.getAChild*() = ae and
    guard.getCondition().toString().matches("%" + vecName + ".size()%")
  ) and
  // In CIccCmmSearch or CIccApplyCmmSearch
  (
    ae.getEnclosingFunction().getDeclaringType().getName().matches("%CmmSearch%") or
    ae.getEnclosingFunction().getDeclaringType().getName().matches("%ApplyCmmSearch%")
  )
select ae,
  "Unchecked access to " + vecName + "[" + ae.getArrayOffset().toString() +
    "] without verifying vector is populated. CWE-125/CWE-787."
