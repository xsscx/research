/**
 * @name Scalar new without std::nothrow
 * @description Finds `new T` (scalar) allocations that do not use std::nothrow.
 *              When processing untrusted ICC profile data, failed allocations
 *              throw std::bad_alloc, preventing graceful error handling.
 *              Use `new (std::nothrow) T` and check for nullptr.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/icc-unsafe-scalar-new
 * @tags security
 *       memory-safety
 *       allocation
 *       exploit-research
 */

import cpp

/**
 * Holds when a NewExpr uses std::nothrow placement (i.e. `new (std::nothrow) T`).
 * Multiple detection strategies are needed because CodeQL's AST representation
 * varies across compiler front-ends and extraction modes.
 */
predicate hasNothrow(NewExpr alloc) {
  exists(alloc.getPlacementPointer())
  or
  alloc.toString().matches("%nothrow%")
  or
  exists(Expr arg |
    arg = alloc.getAChild() and
    arg.getType().stripType().getName() = "nothrow_t"
  )
  or
  // Check allocator function signature: operator new(size_t, const nothrow_t&)
  exists(FunctionCall allocCall |
    allocCall = alloc.getAllocatorCall() and
    allocCall.getTarget().getAParameter().getType().stripType().getName() = "nothrow_t"
  )
}

from NewExpr alloc
where
  // Not using nothrow placement
  not hasNothrow(alloc) and
  // Only flag ICC-related types (CIccProfile, CIccTag*, etc.)
  alloc.getAllocatedType().getName().matches("CIcc%") and
  // Exclude upstream iccDEV code
  not alloc.getFile().toString().matches("%iccDEV%") and
  not alloc.getFile().toString().matches("%test%")
select alloc,
  "Scalar allocation `new " + alloc.getAllocatedType().getName() +
    "` does not use std::nothrow. Use `new (std::nothrow) " +
    alloc.getAllocatedType().getName() + "` and check for nullptr."
