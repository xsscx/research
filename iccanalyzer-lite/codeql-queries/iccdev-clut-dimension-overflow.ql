/**
 * @name Integer overflow in CLUT/LUT dimension product
 * @description Detects multiplication of grid dimensions (inputChannels *
 *              outputChannels * gridPoints^N) without 64-bit widening or
 *              overflow checks. These products size CLUT allocations and
 *              can overflow uint32 with attacker-controlled channel counts
 *              or grid sizes (CWE-190).
 * @kind problem
 * @id icc/clut-dimension-overflow
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-190
 *       iccdev
 */

import cpp

/**
 * ICC profile class that handles multi-dimensional LUT data.
 */
class IccLutClass extends Class {
  IccLutClass() {
    this.getName().regexpMatch("CIccCLUT|CIccMBB|CIccTagLut8|CIccTagLut16|CIccTagLutAtoB|CIccTagLutBtoA|CIccMpeEmissionCLUT|CIccMpeReflectanceCLUT")
  }
}

/**
 * A multiplication involving grid/channel member variables.
 */
class GridDimensionMultiply extends MulExpr {
  GridDimensionMultiply() {
    exists(Expr operand |
      operand = this.getAnOperand() and
      (
        exists(FieldAccess fa |
          fa = operand.getAChild*() and
          fa.getTarget().getName().regexpMatch("m_nInput|m_nOutput|m_nGridPoints|m_nPrecision|m_nReservedByte|nGrid|nInput|nOutput|m_nMaxGridPoint|m_nNumGridPoints")
        )
        or
        exists(ArrayExpr ae |
          ae = operand.getAChild*() and
          exists(FieldAccess fa2 |
            fa2 = ae.getArrayBase() and
            fa2.getTarget().getName().regexpMatch("m_GridPoints|m_nGridPoints|GridPoints")
          )
        )
      )
    ) and
    // Only flag 32-bit or narrower multiplications
    this.getType().getSize() <= 4
  }
}

/**
 * A function in an ICC LUT class or CLUT-related code.
 */
class LutFunction extends MemberFunction {
  LutFunction() {
    this.getDeclaringType() instanceof IccLutClass
    or
    this.getDeclaringType().getName().regexpMatch("CIccMpe.*") and
    this.getName().regexpMatch("Read|Begin|SetData|Init|Interp.*")
  }
}

from GridDimensionMultiply mul, LutFunction func
where
  mul.getEnclosingFunction() = func and
  // No widening cast to 64-bit before the multiply
  not exists(CStyleCast cast |
    cast.getAChild*() = mul and
    cast.getType().getSize() >= 8
  ) and
  not exists(StaticCast cast |
    cast.getAChild*() = mul and
    cast.getType().getSize() >= 8
  )
select mul,
  "32-bit multiplication of grid/channel dimensions in " +
    func.getDeclaringType().getName() + "::" + func.getName() +
    " may overflow before allocation (CWE-190)"
