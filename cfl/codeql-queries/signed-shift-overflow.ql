/**
 * @name Signed integer shift overflow
 * @description Finds left-shift expressions where an unsigned char is implicitly
 *              promoted to signed int before shifting. When bit 7 is set and the
 *              shift is >= 24, the result overflows signed int (UB in C/C++).
 *              Cast operands to uint32_t before shifting.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/icc-signed-shift-overflow
 * @tags security
 *       correctness
 *       undefined-behavior
 *       exploit-research
 */

import cpp

from LShiftExpr shift
where
  // Left operand is a byte-sized type (unsigned char / uint8_t)
  shift.getLeftOperand().getType().getSize() = 1 and
  // Right operand is a constant >= 24 (the dangerous range)
  shift.getRightOperand().getValue().toInt() >= 24 and
  // The shift itself has signed type (implicit promotion to int)
  shift.getType().(IntegralType).isSigned() and
  // Exclude upstream iccDEV
  not shift.getFile().toString().matches("%iccDEV%")
select shift,
  "Left shift of byte value by " + shift.getRightOperand().getValue() +
    " bits causes signed integer overflow (UB) when bit 7 is set. " +
    "Cast to uint32_t before shifting."
