/**
 * @name Array new without std::nothrow
 * @description Finds `new T[size]` allocations that do not use std::nothrow.
 *              When size comes from untrusted input (ICC profile data), a failed
 *              allocation throws std::bad_alloc instead of returning nullptr,
 *              making graceful error handling impossible. All variable-size
 *              array allocations should use `new (std::nothrow) T[size]`.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/icc-unsafe-array-new
 * @tags security
 *       memory-safety
 *       allocation
 *       exploit-research
 */

import cpp

/**
 * Holds when a NewArrayExpr uses std::nothrow placement.
 */
predicate hasNothrowArray(NewArrayExpr alloc) {
  exists(alloc.getPlacementPointer())
  or
  alloc.toString().matches("%nothrow%")
  or
  exists(Expr arg |
    arg = alloc.getAChild() and
    arg.getType().stripType().getName() = "nothrow_t"
  )
}

from NewArrayExpr alloc
where
  // Only flag array new (variable-size), not scalar new
  exists(alloc.getArraySize()) and
  // Not using nothrow placement
  not hasNothrowArray(alloc) and
  // Exclude upstream iccDEV code (not ours to fix)
  not alloc.getFile().toString().matches("%iccDEV%") and
  // Exclude test files
  not alloc.getFile().toString().matches("%test%")
select alloc,
  "Array allocation `new " + alloc.getAllocatedType().getName() + "[...]` " +
    "does not use std::nothrow. If size is attacker-controlled, " +
    "this throws std::bad_alloc on OOM instead of returning nullptr."
