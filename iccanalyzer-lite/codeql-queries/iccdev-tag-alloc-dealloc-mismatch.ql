/**
 * @name Alloc-dealloc mismatch in ICC tag classes
 * @description Detects classes where a member field is allocated with new[]
 *              in one method but freed with free() or scalar delete in another.
 *              These cause heap corruption when processing untrusted profiles
 *              (CWE-762). Cross-reference with iccanalyzer-lite H157.
 * @kind problem
 * @id icc/tag-alloc-dealloc-mismatch
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-762
 *       iccdev
 */

import cpp

/**
 * ICC tag or profile class.
 */
class IccClass extends Class {
  IccClass() {
    this.getName().matches("CIcc%")
  }
}

/**
 * Holds if `nae` is a new[] expression in a method of class `c`
 * that is assigned to a field named `fieldName`.
 */
predicate newArrayToField(IccClass c, string fieldName, NewArrayExpr nae) {
  exists(MemberFunction mf, AssignExpr assign, FieldAccess fa |
    nae.getEnclosingFunction() = mf and
    mf.getDeclaringType() = c and
    assign.getRValue().getAChild*() = nae and
    fa = assign.getLValue().getAChild*() and
    fa.getTarget().getName() = fieldName
  )
}

/**
 * Holds if free() is called on a field named `fieldName` in class `c`.
 */
predicate freeOnField(IccClass c, string fieldName, FunctionCall fc) {
  exists(MemberFunction mf, FieldAccess fa |
    fc.getTarget().getName() = "free" and
    fc.getEnclosingFunction() = mf and
    mf.getDeclaringType() = c and
    fa = fc.getArgument(0).getAChild*() and
    fa.getTarget().getName() = fieldName
  )
}

/**
 * Holds if scalar delete is called on a field named `fieldName` in class `c`.
 */
predicate scalarDeleteOnField(IccClass c, string fieldName, DeleteExpr de) {
  exists(MemberFunction mf, FieldAccess fa |
    de.getEnclosingFunction() = mf and
    mf.getDeclaringType() = c and
    fa = de.getExpr().getAChild*() and
    fa.getTarget().getName() = fieldName
  )
}

from IccClass c, string fieldName, NewArrayExpr nae, Expr freeOp, string mismatchType
where
  newArrayToField(c, fieldName, nae) and
  (
    (exists(FunctionCall fc | freeOnField(c, fieldName, fc) and freeOp = fc) and mismatchType = "free()")
    or
    (exists(DeleteExpr de | scalarDeleteOnField(c, fieldName, de) and freeOp = de) and mismatchType = "scalar delete")
  )
select freeOp,
  "Field '" + fieldName + "' in " + c.getName() +
    " allocated with new[] but freed with " + mismatchType + " (CWE-762, H157). " +
    "Allocated at " + nae.getLocation().getFile().getBaseName() + ":" +
    nae.getLocation().getStartLine().toString()
