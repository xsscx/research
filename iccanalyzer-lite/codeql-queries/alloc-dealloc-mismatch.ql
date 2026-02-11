/**
 * @name Alloc-Dealloc Mismatch Detection
 * @description Finds mismatched allocation/deallocation pairs (e.g., new[] with free(),
 *              malloc with delete) which cause undefined behavior. Covers both local
 *              variables and class member fields across methods.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-alloc-dealloc-mismatch
 * @tags security
 *       memory-safety
 *       alloc-dealloc-mismatch
 *       exploit-research
 */

import cpp

/** Holds if `alloc` is a new[] expression that assigns to variable `v`. */
predicate newArrayAllocTo(NewArrayExpr alloc, Variable v) {
  exists(AssignExpr assign |
    assign.getRValue().getAChild*() = alloc and
    v = assign.getLValue().(VariableAccess).getTarget()
  )
  or
  v.getInitializer().getExpr().getAChild*() = alloc
}

/** Holds if `alloc` is a malloc/calloc/realloc call that assigns to variable `v`. */
predicate cAllocTo(FunctionCall alloc, Variable v) {
  alloc.getTarget().getName() in ["malloc", "calloc", "realloc"] and
  (
    exists(AssignExpr assign |
      assign.getRValue().getAChild*() = alloc and
      v = assign.getLValue().(VariableAccess).getTarget()
    )
    or
    v.getInitializer().getExpr().getAChild*() = alloc
  )
}

/** Gets the variable freed by a free() call. */
Variable getFreedVar(FunctionCall fc) {
  fc.getTarget().getName() = "free" and
  result = fc.getArgument(0).(VariableAccess).getTarget()
}

/** Gets the variable deleted by a delete expression. */
Variable getDeletedVar(DeleteExpr de) {
  result = de.getExpr().(VariableAccess).getTarget()
}

/** Gets the variable deleted by a delete[] expression. */
Variable getDeleteArrayVar(DeleteArrayExpr de) {
  result = de.getExpr().(VariableAccess).getTarget()
}

/** Holds if two expressions operate on the same variable in a related scope. */
predicate sameVariableScope(Expr allocExpr, Expr deallocExpr, Variable v) {
  v instanceof MemberVariable and
  allocExpr.getEnclosingFunction().getDeclaringType() =
    deallocExpr.getEnclosingFunction().getDeclaringType()
  or
  not v instanceof MemberVariable and
  allocExpr.getEnclosingFunction() = deallocExpr.getEnclosingFunction()
}

/**
 * Finds all alloc-dealloc mismatches and returns the dealloc site, variable,
 * alloc site, alloc kind, and dealloc kind.
 */
predicate allocDeallocMismatch(
  Expr deallocSite, Variable v, Expr allocSite, string allocKind, string deallocKind
) {
  // new[] freed with free()
  exists(NewArrayExpr alloc, FunctionCall dealloc |
    newArrayAllocTo(alloc, v) and
    v = getFreedVar(dealloc) and
    sameVariableScope(alloc, dealloc, v) and
    allocSite = alloc and deallocSite = dealloc and
    allocKind = "new[]" and deallocKind = "free()"
  )
  or
  // new[] freed with scalar delete
  exists(NewArrayExpr alloc, DeleteExpr dealloc |
    newArrayAllocTo(alloc, v) and
    v = getDeletedVar(dealloc) and
    sameVariableScope(alloc, dealloc, v) and
    allocSite = alloc and deallocSite = dealloc and
    allocKind = "new[]" and deallocKind = "delete"
  )
  or
  // malloc/calloc/realloc freed with delete[]
  exists(FunctionCall alloc, DeleteArrayExpr dealloc |
    cAllocTo(alloc, v) and
    v = getDeleteArrayVar(dealloc) and
    sameVariableScope(alloc, dealloc, v) and
    allocSite = alloc and deallocSite = dealloc and
    allocKind = alloc.getTarget().getName() + "()" and deallocKind = "delete[]"
  )
  or
  // malloc/calloc/realloc freed with scalar delete
  exists(FunctionCall alloc, DeleteExpr dealloc |
    cAllocTo(alloc, v) and
    v = getDeletedVar(dealloc) and
    sameVariableScope(alloc, dealloc, v) and
    allocSite = alloc and deallocSite = dealloc and
    allocKind = alloc.getTarget().getName() + "()" and deallocKind = "delete"
  )
}

from Expr deallocSite, Variable v, Expr allocSite, string allocKind, string deallocKind
where allocDeallocMismatch(deallocSite, v, allocSite, allocKind, deallocKind)
select deallocSite,
  "Alloc-dealloc mismatch: '" + v.getName() + "' allocated with " + allocKind + " at $@ but freed with " + deallocKind + " here.",
  allocSite, allocSite.getLocation().getFile().getBaseName() + ":" + allocSite.getLocation().getStartLine().toString()
