/**
 * @name Uninitialized variable use in profile parsing
 * @description Finds local variables that may be used before initialization,
 *              particularly in ICC profile tag reading and data conversion
 *              paths where partial reads leave fields uninitialized.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id cpp/icc-uninitialized-read
 * @tags security
 *       memory-safety
 *       uninitialized-read
 *       exploit-research
 */

import cpp

from LocalVariable v, VariableAccess use
where
  // Variable declared without initializer
  not exists(v.getInitializer())
  // Arithmetic, pointer, or enum type (not class/struct with constructor)
  and (
    v.getUnspecifiedType() instanceof ArithmeticType
    or v.getUnspecifiedType() instanceof PointerType
    or v.getUnspecifiedType() instanceof Enum
  )
  // Used (read) somewhere
  and use.getTarget() = v
  and use.isRValue()
  // The use is not itself an assignment target
  and not exists(Assignment a | a.getLValue() = use)
  // No assignment dominates this use
  and not exists(Assignment a, VariableAccess lhs |
    a.getLValue() = lhs
    and lhs.getTarget() = v
    and a.getBasicBlock().getASuccessor*() = use.getBasicBlock()
    and a != use.getParent()
  )
  // Exclude memset/memcpy initialization patterns
  and not exists(FunctionCall init |
    init.getTarget().getName() in ["memset", "memcpy", "bzero", "ZeroMemory"]
    and init.getArgument(0).getAChild*().(VariableAccess).getTarget() = v
  )
  // Exclude iccDEV upstream
  and not v.getFile().toString().matches("%iccDEV%")
  and not use.getFile().toString().matches("%iccDEV%")
select use, "Variable '" + v.getName() +
  "' of type " + v.getType().toString() +
  " may be used before initialization"
