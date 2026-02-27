/**
 * @name IccAnalyzer Security Analysis
 * @description Finds potential security issues in IccAnalyzer tool
 * @kind problem
 * @problem.severity warning
 * @id cpp/iccanalyzer-security
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

// Find unchecked file operations (fread/fwrite only, not C++ stream methods)
class UncheckedFileRead extends FunctionCall {
  UncheckedFileRead() {
    this.getTarget().getName() in ["fread", "fwrite"] and
    this.getFile().getBaseName().matches("IccAnalyzer%") and
    not exists(BinaryOperation cmp | 
      cmp.getAnOperand() = this or
      cmp.getAnOperand().(VariableAccess).getTarget().getAnAssignedValue() = this
    )
  }
}

// Find potential integer overflows in multiplication
// Excludes: compile-time constants, loop index arithmetic (i*8 etc)
class IntegerOverflowMultiply extends MulExpr {
  IntegerOverflowMultiply() {
    this.getFile().getBaseName().matches("IccAnalyzer%") and
    // Exclude compile-time constant expressions
    not this.isConstant() and
    // Exclude multiplications where both operands are compile-time constants
    not (this.getLeftOperand().isConstant() and this.getRightOperand().isConstant()) and
    // Exclude small loop index multiplications (e.g., i*8)
    not exists(Literal lit |
      lit = this.getAnOperand() and
      lit.getValue().toInt() <= 64
    ) and
    // Must be in a function (not namespace scope)
    exists(this.getEnclosingFunction()) and
    not exists(IfStmt guard |
      guard.getCondition().getAChild*() instanceof RelationalOperation and
      guard.getControlFlowScope() = this.getEnclosingFunction()
    )
  }
}

// Find buffer allocations without size checks
// Checks for any bounds-checking if-statement within 30 lines before allocation
class UnsafeBufferAllocation extends NewArrayExpr {
  UnsafeBufferAllocation() {
    this.getFile().getBaseName().matches("IccAnalyzer%") and
    // Exclude allocations using std::nothrow (they return nullptr on failure)
    not this.toString().matches("%nothrow%") and
    not exists(this.getPlacementPointer()) and
    not exists(Expr arg |
      arg = this.getAChild() and
      arg.getType().stripType().getName() = "nothrow_t"
    ) and
    // Must not have any size/bounds guard within 30 lines before
    not exists(IfStmt check |
      check.getEnclosingFunction() = this.getEnclosingFunction() and
      check.getLocation().getStartLine() < this.getLocation().getStartLine() and
      check.getLocation().getStartLine() > this.getLocation().getStartLine() - 30 and
      check.getCondition().getAChild*() instanceof RelationalOperation
    )
  }
}

// Find resource leaks (fopen without fclose on all paths)
// Allows fclose in the same class (e.g. destructor) or same function
class ResourceLeak extends FunctionCall {
  ResourceLeak() {
    this.getTarget().getName() = "fopen" and
    this.getFile().getBaseName().matches("IccAnalyzer%") and
    not exists(FunctionCall close |
      close.getTarget().getName() = "fclose" and
      (
        close.getEnclosingFunction() = this.getEnclosingFunction() or
        close.getEnclosingFunction().getDeclaringType() = this.getEnclosingFunction().getDeclaringType()
      )
    )
  }
}

from Element e
where e instanceof UncheckedFileRead or
      e instanceof IntegerOverflowMultiply or
      e instanceof UnsafeBufferAllocation or
      e instanceof ResourceLeak
select e, "Security issue detected in IccAnalyzer"
