/**
 * @name Describe() accesses m_params without bounds check
 * @description Detects Describe() methods that access indexed elements of
 *              parameter arrays (m_params, m_nParameters) without first
 *              verifying the array has enough elements for the function type.
 *              This is the exact pattern fixed by CFL-050 (FormulaCurveSegment)
 *              and CFL-051 (ParametricCurve). A malformed profile can set
 *              m_nFunctionType to a value requiring N params but provide fewer,
 *              causing heap-buffer-overflow in Describe().
 * @kind problem
 * @id icc/describe-param-bounds
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-122
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A Describe() method on a CIcc* class.
 */
class IccDescribeMethod extends MemberFunction {
  IccDescribeMethod() {
    this.getName() = "Describe" and
    this.getDeclaringType().getName().matches("CIcc%")
  }
}

/**
 * An array subscript access on a member field named m_params or m_Params
 * or GetParams().
 */
class ParamArrayAccess extends ArrayExpr {
  ParamArrayAccess() {
    exists(Expr base |
      base = this.getArrayBase() and
      (
        base.(FieldAccess).getTarget().getName().matches("m_%Param%") or
        base.(FieldAccess).getTarget().getName().matches("m_%param%") or
        base.(FunctionCall).getTarget().getName().matches("Get%Param%")
      )
    )
  }
}

from IccDescribeMethod dm, ParamArrayAccess paa
where
  paa.getEnclosingFunction() = dm and
  // No preceding bounds check in the same switch case or if block
  not exists(IfStmt guard |
    guard.getEnclosingFunction() = dm and
    guard.getLocation().getStartLine() < paa.getLocation().getStartLine() and
    exists(Expr cond | cond = guard.getCondition().getAChild*() |
      cond.(FieldAccess).getTarget().getName().matches("m_n%Param%") or
      cond.(FieldAccess).getTarget().getName().matches("m_nParameters") or
      cond.(FunctionCall).getTarget().getName().matches("GetNum%Param%")
    )
  )
select paa,
  "Array access on parameter data in " +
    dm.getDeclaringType().getName() + "::Describe() at index [" +
    paa.getArrayOffset().toString() +
    "] without verifying m_nParameters >= required count — " +
    "heap-buffer-overflow if profile has fewer params than funcType expects " +
    "(CWE-125, CFL-050/CFL-051 pattern)"
