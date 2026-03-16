/**
 * @name Use-after-free in ICC tag ownership transfer
 * @description Detects patterns where ICC profile pointers are used after
 *              ownership transfer or where member fields are accessed after
 *              Cleanup() frees member data. The CFL-003 pattern: copy
 *              constructor uses new[] but Cleanup() uses free() (CWE-416).
 *              Cross-reference with iccanalyzer-lite H159.
 * @kind problem
 * @id icc/tag-ownership-uaf
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-416
 *       iccdev
 */

import cpp

/**
 * A CIcc class.
 */
class IccClass extends Class {
  IccClass() {
    this.getName().matches("CIcc%")
  }
}

/**
 * A Cleanup() method that frees member data.
 */
class CleanupMethod extends MemberFunction {
  CleanupMethod() {
    this.getName() = "Cleanup" and
    this.getDeclaringType() instanceof IccClass
  }
}

from Expr finding, string msg
where
  // Pattern 1: Member field accessed after Cleanup() call in same function
  exists(FunctionCall cc, FieldAccess fa, MemberFunction mf |
    cc.getTarget() instanceof CleanupMethod and
    cc.getEnclosingFunction() = mf and
    mf.getDeclaringType() instanceof IccClass and
    fa.getEnclosingFunction() = mf and
    fa.getLocation().getStartLine() > cc.getLocation().getStartLine() and
    fa.getTarget().getDeclaringType() = cc.getTarget().(MemberFunction).getDeclaringType() and
    not exists(AssignExpr assign | assign.getLValue().getAChild*() = fa) and
    not exists(EqualityOperation eq | eq.getAnOperand().getAChild*() = fa) and
    fa.getTarget().getType() instanceof PointerType and
    finding = fa and
    msg = "Member '" + fa.getTarget().getName() + "' in " +
      mf.getDeclaringType().getName() + "::" + mf.getName() +
      " accessed after Cleanup() call — potential UAF (CWE-416, H159)"
  )
  or
  // Pattern 2: CFL-003 — new[] in copy/assign but free() in Cleanup/destructor
  exists(NewArrayExpr nae, FunctionCall fc, IccClass c |
    exists(MemberFunction copyOrAssign |
      nae.getEnclosingFunction() = copyOrAssign and
      copyOrAssign.getDeclaringType() = c and
      (
        copyOrAssign instanceof CopyConstructor or
        copyOrAssign instanceof CopyAssignmentOperator or
        copyOrAssign.getName() = "operator="
      )
    ) and
    fc.getTarget().getName() = "free" and
    exists(MemberFunction cleanup |
      fc.getEnclosingFunction() = cleanup and
      cleanup.getDeclaringType() = c and
      cleanup.getName().regexpMatch("Cleanup|~.*")
    ) and
    finding = nae and
    msg = "Class " + c.getName() +
      " uses new[] in copy/assign but free() in Cleanup/destructor — " +
      "alloc-dealloc mismatch leads to UAF on copy (CWE-416/CWE-762, H159)"
  )
select finding, msg
