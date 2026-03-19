/**
 * @name Constructor does not initialize all scalar members
 * @description Detects CIcc* class constructors where scalar member fields
 *              (bool, int, enum, float, double) are not initialized. Uninitialized
 *              members lead to undefined behavior when serialized (toJson) or
 *              compared. This is the exact pattern fixed by CFL-057
 *              (CIccCfgSearchApply had empty constructor, 6 scalars uninitialized).
 * @kind problem
 * @id icc/uninitialized-constructor-member
 * @problem.severity error
 * @security-severity 6.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-908
 *       external/cwe/cwe-457
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A CIcc* or CIccCfg* class.
 */
class IccClass extends Class {
  IccClass() {
    this.getName().matches("CIcc%")
  }
}

/**
 * A scalar member field (bool, int, enum, float, double, pointer).
 */
class ScalarMember extends Field {
  ScalarMember() {
    this.getDeclaringType() instanceof IccClass and
    (
      this.getType().getUnspecifiedType() instanceof IntegralType or
      this.getType().getUnspecifiedType() instanceof FloatingPointType or
      this.getType().getUnspecifiedType() instanceof Enum or
      this.getType().getUnspecifiedType() instanceof PointerType or
      this.getType().getUnspecifiedType() instanceof BoolType
    ) and
    // Exclude static members
    not this.isStatic()
  }
}

from Constructor ctor, IccClass cls, ScalarMember field
where
  ctor.getDeclaringType() = cls and
  field.getDeclaringType() = cls and
  // Only report findings in our code — exclude upstream iccDEV library
  not ctor.getLocation().getFile().getRelativePath().matches("iccDEV/%") and
  not ctor.getLocation().getFile().getRelativePath().matches("cfl/iccDEV/%") and
  // Constructor is explicitly defined (not compiler-generated)
  not ctor.isCompilerGenerated() and
  // Default constructor (no parameters, or only default params)
  ctor.getNumberOfParameters() = 0 and
  // The field is not initialized in the constructor body
  not exists(AssignExpr ae |
    ae.getEnclosingFunction() = ctor and
    ae.getLValue().(FieldAccess).getTarget() = field
  ) and
  // The field is not initialized in the initializer list
  not exists(ConstructorFieldInit cfi |
    cfi.getEnclosingFunction() = ctor and
    cfi.getTarget() = field
  ) and
  // Not initialized by a reset() call in the constructor
  not exists(FunctionCall resetCall |
    resetCall.getEnclosingFunction() = ctor and
    resetCall.getTarget().getName() = "reset"
  )
select ctor,
  cls.getName() + " default constructor does not initialize scalar member '" +
    field.getName() + "' (" + field.getType().getName() +
    ") — reads from this field produce undefined behavior " +
    "(CWE-908, CFL-057 pattern)"
