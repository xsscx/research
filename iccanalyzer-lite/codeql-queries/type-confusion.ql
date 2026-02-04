/**
 * @name Type Confusion Detection
 * @description Finds type confusion vulnerabilities in virtual function calls
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/icc-type-confusion
 * @tags security
 *       type-safety
 *       type-confusion
 *       exploit-research
 */

import cpp

/**
 * A cast that may introduce type confusion
 */
class SuspiciousCast extends Cast {
  SuspiciousCast() {
    // Cast between unrelated class types
    exists(Class fromClass, Class toClass |
      fromClass = this.getExpr().getType().getUnspecifiedType() and
      toClass = this.getType().getUnspecifiedType() and
      fromClass != toClass and
      not fromClass.derivesFrom(toClass) and
      not toClass.derivesFrom(fromClass)
    )
    or
    // C-style cast (less safe than static_cast)
    this instanceof CStyleCast and
    this.getType().getUnspecifiedType() instanceof Class
    or
    // Reinterpret cast to class type (very dangerous)
    this instanceof ReinterpretCast and
    this.getType().getUnspecifiedType() instanceof Class
  }
}

/**
 * Virtual function call on potentially confused type
 */
class ConfusedVirtualCall extends FunctionCall {
  ConfusedVirtualCall() {
    this.isVirtual() and
    exists(SuspiciousCast cast, Variable v |
      cast.getAChild*() = v.getInitializer().getExpr() and
      this.getQualifier() = v.getAnAccess()
    )
  }
  
  SuspiciousCast getSuspiciousCast() {
    exists(Variable v |
      result.getAChild*() = v.getInitializer().getExpr() and
      this.getQualifier() = v.getAnAccess()
    )
  }
}

/**
 * Type signature checking patterns (good)
 */
class TypeSignatureCheck extends IfStmt {
  TypeSignatureCheck() {
    exists(FunctionCall fc |
      fc.getTarget().getName() in ["GetType", "getType", "GetTypeSignature"] and
      this.getCondition().getAChild*() = fc
    )
  }
}

/**
 * Object creation from untrusted type field
 */
class UntrustedTypeFactory extends FunctionCall {
  UntrustedTypeFactory() {
    this.getTarget().getName().matches("%Create%") and
    exists(Variable typeVar |
      this.getAnArgument() = typeVar.getAnAccess() and
      typeVar.getType().getName().matches("%Signature%")
    )
  }
}

from ConfusedVirtualCall call, SuspiciousCast cast, string message
where
  cast = call.getSuspiciousCast() and
  // No type signature validation before virtual call
  not exists(TypeSignatureCheck check |
    check.getLocation().getEndLine() < call.getLocation().getStartLine() and
    check.getEnclosingFunction() = call.getEnclosingFunction()
  ) and
  message = "Type confusion: Virtual function call on object obtained through suspicious cast. " +
            "May cause incorrect vtable dispatch."
select call, message, cast, "Suspicious cast location"
