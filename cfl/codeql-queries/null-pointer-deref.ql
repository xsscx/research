/**
 * @name Null pointer dereference after allocation or lookup
 * @description Finds pointer dereferences where the pointer may be null
 *              from a failed allocation, failed lookup, or unchecked return.
 *              Focused on ICC profile parsing patterns where GetTagEntry,
 *              FindTag, malloc, new return null on failure.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id cpp/icc-null-pointer-deref
 * @tags security
 *       memory-safety
 *       null-dereference
 *       exploit-research
 */

import cpp

/**
 * A function call that may return null on failure.
 */
class NullableCall extends FunctionCall {
  NullableCall() {
    this.getTarget().getName() in [
      "malloc", "calloc", "realloc",
      "strdup", "strndup",
      "fopen", "tmpfile",
      "GetTagEntry", "FindTag", "GetTag",
      "LoadTag", "GetElement",
      "dynamic_cast"
    ]
    or (
      this.getTarget().getUnspecifiedType() instanceof PointerType
      and this.getTarget().getName().matches("Get%")
    )
  }
}

from NullableCall alloc, VariableAccess deref, Variable v
where
  v.getAnAssignedValue() = alloc
  and deref.getTarget() = v
  and deref.getParent() instanceof PointerDereferenceExpr
  // Not guarded by a null check via if/while/for
  and not exists(ControlStructure cs, VariableAccess va |
    va.getTarget() = v
    and cs.getControllingExpr().getAChild*() = va
    and cs.getAChild*() = deref
  )
  // Exclude iccDEV upstream (not our code)
  and not alloc.getFile().toString().matches("%iccDEV%")
  and not deref.getFile().toString().matches("%iccDEV%")
select deref, "Pointer '" + v.getName() + "' may be null (from " +
  alloc.getTarget().getName() + ") and is dereferenced without null check"
