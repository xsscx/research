/**
 * @name C-style cast to ICC tag type
 * @description Finds C-style casts to CIccTag subclasses (CIccMBB, CIccCLUT,
 *              CIccTagMultiProcessElement, etc.). These should use dynamic_cast
 *              with a null check to prevent type confusion when a malicious
 *              profile returns an unexpected tag type from FindTag/LoadTag.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/icc-tag-cstyle-cast
 * @tags security
 *       type-safety
 *       type-confusion
 *       exploit-research
 */

import cpp

class IccTagSubclass extends Class {
  IccTagSubclass() {
    this.getName().matches("CIcc%") and
    (
      this.getName() in [
        "CIccMBB", "CIccCLUT", "CIccTagMultiProcessElement",
        "CIccTagNamedColor2", "CIccTagXYZ", "CIccTagCurve",
        "CIccTagParametricCurve", "CIccTagLut16", "CIccTagLut8",
        "CIccTagLutAtoB", "CIccTagLutBtoA",
        "CIccTagSpectralViewingConditions",
        "CIccTagSparseMatrixArray", "CIccTagStruct"
      ]
      or
      exists(Class parent |
        this.derivesFrom(parent) and
        parent.getName() = "CIccTag"
      )
    )
  }
}

from CStyleCast cast, IccTagSubclass targetType
where
  targetType = cast.getType().getUnspecifiedType().(PointerType).getBaseType() and
  // Exclude iccDEV upstream
  not cast.getFile().toString().matches("%iccDEV%") and
  // Exclude test files
  not cast.getFile().toString().matches("%test%")
select cast,
  "C-style cast to " + targetType.getName() +
    "* should use dynamic_cast with null check to prevent " +
    "type confusion from malicious ICC profiles."
