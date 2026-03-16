/**
 * @name Uncontrolled allocation size from ICC profile Read()
 * @description Detects allocations in Read() methods sized by member fields
 *              that hold values deserialized from ICC profile data.
 *              Attacker-controlled tag sizes can trigger arbitrarily large
 *              allocations (CWE-789). Cross-reference with iccanalyzer-lite H154.
 * @kind problem
 * @id icc/read-allocation-overflow
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-789
 *       iccdev
 */

import cpp

/**
 * A CIcc class Read() method that deserializes binary ICC profile data.
 */
class IccReadMethod extends MemberFunction {
  IccReadMethod() {
    this.getName() = "Read" and
    this.getDeclaringType().getName().matches("CIcc%")
  }
}

from NewArrayExpr nae, IccReadMethod readMethod, FieldAccess fa
where
  nae.getEnclosingFunction() = readMethod and
  // The size sub-expression references a member field (file-controlled)
  fa = nae.getAChild+() and
  fa instanceof FieldAccess and
  fa.getTarget().getDeclaringType().getName().matches("CIcc%")
select nae,
  "new[] in " + readMethod.getDeclaringType().getName() + "::" + readMethod.getName() +
    " sized by member field '" + fa.getTarget().getName() +
    "' — attacker-controlled allocation size (CWE-789, H154)"
