/**
 * @name Signed integer shift overflow
 * @description Finds left-shift expressions where a byte-sized value is implicitly
 *              promoted to signed int before shifting. Signed char inputs with bit 7
 *              set can shift negative promoted values even at 8-bit shifts. Cast
 *              operands to uint32_t before shifting.
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
  // Right operand is a constant >= 8 (ICC two/four byte signature assembly)
  shift.getRightOperand().getValue().toInt() >= 8 and
  // The shift itself has signed type (implicit promotion to int)
  shift.getType().(IntegralType).isSigned()
select shift,
  "Left shift of byte value by " + shift.getRightOperand().getValue() +
    " bits causes signed integer overflow (UB) when bit 7 is set. " +
    "Cast to uint32_t before shifting."
