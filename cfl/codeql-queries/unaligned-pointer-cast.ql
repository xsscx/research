/**
 * @name Unaligned pointer cast via reinterpret_cast
 * @description Finds reinterpret_cast from byte pointers to wider integer types,
 *              which causes undefined behavior on architectures requiring aligned
 *              access. Use memcpy() instead.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-unaligned-pointer-cast
 * @tags security
 *       correctness
 *       undefined-behavior
 *       exploit-research
 */

import cpp

from ReinterpretCast cast
where
  // Target type is a pointer to a multi-byte integer
  cast.getType().(PointerType).getBaseType().getSize() > 1 and
  // Source type is a pointer to a single-byte type (char, unsigned char, uint8_t)
  cast.getExpr().getType().(PointerType).getBaseType().getSize() = 1 and
  // Exclude upstream iccDEV code
  not cast.getFile().toString().matches("%iccDEV%") and
  not cast.getFile().toString().matches("%test%")
select cast,
  "Unaligned reinterpret_cast from byte pointer to " +
    cast.getType().toString() +
    ". This is undefined behavior if the source pointer is not properly aligned. Use memcpy() instead."
