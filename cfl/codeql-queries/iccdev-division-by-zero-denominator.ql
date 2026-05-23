/**
 * @name ICC division denominator lacks local zero guard
 * @description Finds iccDEV denominator expressions from manually proven
 *              division-by-zero bug classes when no nearby pre-division zero
 *              guard is present.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/icc-division-by-zero-denominator
 * @tags security
 *       correctness
 *       division-by-zero
 *       exploit-research
 */

import cpp

predicate isIccDbzFile(File f) {
  f.toString().matches("%IccCAM.cpp") or
  f.toString().matches("%IccCmm.cpp")
}

predicate isKnownDbzDenominator(Expr denom) {
  denom.toString().matches("%m_rgbWhite%") or
  denom.toString().matches("%H_Function%") or
  denom.toString().matches("%mediaXYZ%") or
  denom.toString().matches("%illumXYZ%")
}

predicate hasNearbyZeroGuard(DivExpr div, Expr denom) {
  exists(IfStmt guard |
    guard.getEnclosingFunction() = div.getEnclosingFunction() and
    guard.getLocation().getEndLine() < div.getLocation().getStartLine() and
    guard.getLocation().getEndLine() > div.getLocation().getStartLine() - 20 and
    guard.getCondition().toString().matches("%" + denom.toString() + "%") and
    (
      guard.getCondition().toString().matches("%== 0%") or
      guard.getCondition().toString().matches("%==0%") or
      guard.getCondition().toString().matches("%!= 0%") or
      guard.getCondition().toString().matches("%!=0%")
    )
  )
}

from DivExpr div, Expr denom
where
  denom = div.getRightOperand() and
  isIccDbzFile(div.getFile()) and
  isKnownDbzDenominator(denom) and
  not hasNearbyZeroGuard(div, denom)
select div, "Division uses ICC profile-controlled denominator '" + denom.toString() +
  "' without a nearby zero guard."
