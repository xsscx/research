/**
 * @name Describe() dereferences member pointer without null check
 * @description Detects Describe() methods that iterate over or dereference
 *              member pointers (m_pWhite, m_pOffset, m_pMatrix, m_pApply, etc.)
 *              without first checking for null. When Read() partially fails or
 *              the profile is malformed, these pointers may remain null, causing
 *              null pointer dereference in Describe().
 *              This is the exact pattern fixed by CFL-056 (SpectralMatrix/Observer).
 * @kind problem
 * @id icc/describe-null-array
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-476
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
 * A field access on a pointer-typed member (m_p* naming convention).
 */
class PointerMemberAccess extends FieldAccess {
  PointerMemberAccess() {
    this.getTarget().getName().matches("m_p%") and
    this.getTarget().getType() instanceof PointerType
  }
}

from IccDescribeMethod dm, PointerMemberAccess pma, ArrayExpr ae
where
  ae.getEnclosingFunction() = dm and
  pma.getEnclosingFunction() = dm and
  // The array base is the same pointer field
  ae.getArrayBase().(FieldAccess).getTarget() = pma.getTarget() and
  // No null check before the access
  not exists(IfStmt guard |
    guard.getEnclosingFunction() = dm and
    guard.getLocation().getStartLine() <= ae.getLocation().getStartLine() and
    exists(Expr cond | cond = guard.getCondition().getAChild*() |
      cond.(FieldAccess).getTarget() = pma.getTarget()
    )
  )
select ae,
  "Array subscript on member pointer '" + pma.getTarget().getName() +
    "' in " + dm.getDeclaringType().getName() + "::Describe()" +
    " without null check — null deref if Read() partially failed " +
    "(CWE-476, CFL-056 pattern)"
