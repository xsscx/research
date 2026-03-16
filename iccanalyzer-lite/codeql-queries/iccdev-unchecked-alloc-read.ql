/**
 * @name Unchecked allocation return value in ICC Read path
 * @description Detects new[] allocations in CIcc* Read/LoadXml/SetData methods
 *              where the return value is not checked for NULL before use.
 *              When processing untrusted ICC profiles, allocation failures
 *              must be handled gracefully (CWE-252). Cross-reference with
 *              iccanalyzer-lite H156.
 * @kind problem
 * @id icc/unchecked-alloc-read
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-252
 *       iccdev
 */

import cpp

/**
 * An ICC deserialization method (Read, LoadXml, SetData, Init).
 */
class IccDeserializeMethod extends MemberFunction {
  IccDeserializeMethod() {
    this.getDeclaringType().getName().matches("CIcc%") and
    this.getName().regexpMatch("Read|LoadXml|SetData|Init|SetSize")
  }
}

from NewArrayExpr nae, IccDeserializeMethod method
where
  nae.getEnclosingFunction() = method and
  // The allocation size involves a member field (file-controlled data)
  exists(FieldAccess fa |
    fa = nae.getAChild+() and
    fa.getTarget().getDeclaringType().getName().matches("CIcc%")
  ) and
  // No null check on any pointer within 5 lines after the allocation
  not exists(IfStmt ifStmt, Expr cond |
    ifStmt.getEnclosingFunction() = method and
    cond = ifStmt.getCondition().getAChild*() and
    (cond instanceof EqualityOperation or cond instanceof NotExpr) and
    ifStmt.getLocation().getStartLine() > nae.getLocation().getStartLine() and
    ifStmt.getLocation().getStartLine() <= nae.getLocation().getStartLine() + 5
  )
select nae,
  "new[] in " + method.getDeclaringType().getName() + "::" +
    method.getName() + " — return value not checked for NULL (CWE-252, H156)"
