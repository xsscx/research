/**
 * @name Enum cast from file-controlled integer in ICC library
 * @description Detects casts from integer types to ICC-specific enum types
 *              (ic* enums) in CIcc* class methods. Without range validation,
 *              these casts produce undefined behavior when the file contains
 *              values outside the enum's defined range (CWE-681).
 *              Cross-reference with iccanalyzer-lite H158.
 * @kind problem
 * @id icc/file-controlled-enum-cast
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-681
 *       iccdev
 */

import cpp

/**
 * A CIcc* class method in a deserialization or execution path.
 */
class IccMethod extends MemberFunction {
  IccMethod() {
    this.getDeclaringType().getName().matches("CIcc%")
  }
}

from Cast c, Enum et, IccMethod mf
where
  c.getEnclosingFunction() = mf and
  // Target type is an ICC enum (ic* prefix)
  c.getType().getUnspecifiedType().(Enum) = et and
  et.getName().matches("ic%") and
  // Source is an integer type
  c.getExpr().getType().getUnspecifiedType() instanceof IntegralType and
  // In a Read/LoadXml/Exec/Apply path (file-controlled data)
  mf.getName().regexpMatch("Read|LoadXml|Exec|Apply|Begin|SetData|Init")
select c,
  "Cast to enum '" + et.getName() + "' in " +
    mf.getDeclaringType().getName() + "::" + mf.getName() +
    " — file-controlled integer without range validation (CWE-681, H158)"
