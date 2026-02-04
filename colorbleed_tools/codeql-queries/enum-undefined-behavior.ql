/**
 * @name Enum Undefined Behavior Detection
 * @description Finds all locations where invalid values are loaded into enum types
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/enum-undefined-behavior
 * @tags security
 *       correctness
 *       undefined-behavior
 *       exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

/**
 * An enum type declaration
 */
class EnumType extends Enum {
  EnumType() { this instanceof Enum }
}

/**
 * A variable with enum type
 */
class EnumVariable extends Variable {
  EnumVariable() { this.getType().getUnspecifiedType() instanceof EnumType }

  EnumType getEnumType() { result = this.getType().getUnspecifiedType() }
}

/**
 * Operations that load untrusted data into enum variables
 */
class UntrustedEnumLoad extends Operation {
  UntrustedEnumLoad() {
    // Assignment from Read/input operation
    exists(AssignExpr assign, EnumVariable v, FunctionCall fc |
      assign.getLValue() = v.getAnAccess() and
      (
        fc.getTarget().getName().matches("%Read%") or
        fc.getTarget().getName().matches("%read%") or
        fc.getTarget().getName().matches("%scan%") or
        fc.getTarget().getName().matches("%parse%") or
        fc.getTarget().getName().matches("%load%")
      ) and
      assign.getRValue().getAChild*() = fc
    )
    or
    // Direct cast from integer to enum
    exists(Cast cast, EnumVariable v |
      cast.getExpr().getType().getUnspecifiedType() instanceof IntegralType and
      cast.getType().getUnspecifiedType() instanceof EnumType and
      v.getAnAccess() = cast.getParent()
    )
  }
}

/**
 * Comparison operations on enum variables without validation
 */
class UnvalidatedEnumComparison extends ComparisonOperation {
  UnvalidatedEnumComparison() {
    exists(EnumVariable v, VariableAccess va |
      va = v.getAnAccess() and
      (
        this.getLeftOperand() = va or
        this.getRightOperand() = va
      ) and
      // The enum value was loaded from untrusted source
      exists(UntrustedEnumLoad load, AssignExpr assign |
        assign.getLValue() = v.getAnAccess() and
        assign.getEnclosingFunction() = this.getEnclosingFunction() and
        // No validation between assignment and comparison
        not exists(IfStmt validation |
          validation.getCondition().getAChild*() = v.getAnAccess() and
          validation.getLocation().getEndLine() < this.getLocation().getStartLine() and
          assign.getLocation().getEndLine() < validation.getLocation().getStartLine()
        )
      )
    )
  }

  EnumVariable getEnumVariable() { result.getAnAccess() = this.getAnOperand() }
}

/**
 * Switch statements on potentially invalid enum values
 */
class UnvalidatedEnumSwitch extends SwitchStmt {
  UnvalidatedEnumSwitch() {
    exists(EnumVariable v |
      this.getExpr() = v.getAnAccess() and
      // Has a default case (good) but enum came from untrusted source
      this.hasDefaultCase() and
      exists(UntrustedEnumLoad load | load.getEnclosingFunction() = this.getEnclosingFunction())
    )
  }
}

from UnvalidatedEnumComparison comp, EnumVariable v, string message
where
  v = comp.getEnumVariable() and
  message =
    "Enum comparison on potentially invalid value loaded from untrusted source. " + "Enum type: " +
      v.getEnumType().getName() + ". " +
      "This can trigger undefined behavior if the loaded value is not in the enum definition."
select comp, message, v, "Enum variable: " + v.getName()
