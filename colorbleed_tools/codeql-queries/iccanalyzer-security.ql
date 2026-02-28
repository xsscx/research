/**
 * @name IccAnalyzer Security Analysis
 * @description Finds potential security issues in IccAnalyzer tool
 * @kind problem
 * @problem.severity warning
 * @id cpp/iccanalyzer-security
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

// Find unchecked file operations
class UncheckedFileRead extends FunctionCall {
  UncheckedFileRead() {
    this.getTarget().getName() in ["fread", "fwrite"] and
    not exists(BinaryOperation cmp | 
      cmp.getAnOperand() = this or
      cmp.getAnOperand().(VariableAccess).getTarget().getAnAssignedValue() = this
    )
  }
}

// Find potential integer overflows in multiplication
class IntegerOverflowMultiply extends MulExpr {
  IntegerOverflowMultiply() {
    this.getFile().getBaseName() = "iccAnalyzer.cpp" and
    not exists(IfStmt guard |
      guard.getCondition().getAChild*() instanceof RelationalOperation and
      guard.getControlFlowScope() = this.getEnclosingFunction()
    )
  }
}

// Find buffer allocations without size checks
class UnsafeBufferAllocation extends NewArrayExpr {
  UnsafeBufferAllocation() {
    this.getFile().getBaseName() = "iccAnalyzer.cpp" and
    // Exclude allocations using std::nothrow
    not this.toString().matches("%nothrow%") and
    not exists(this.getPlacementPointer()) and
    not exists(Expr arg |
      arg = this.getAChild() and
      arg.getType().stripType().getName() = "nothrow_t"
    ) and
    // Check allocator function signature: operator new[](size_t, const nothrow_t&)
    not exists(FunctionCall allocCall |
      allocCall = this.getAllocatorCall() and
      allocCall.getTarget().getAParameter().getType().stripType().getName() = "nothrow_t"
    ) and
    not exists(IfStmt check |
      check.getCondition().toString().matches("%fileSize%") and
      check.getLocation().getStartLine() < this.getLocation().getStartLine() and
      check.getLocation().getStartLine() > this.getLocation().getStartLine() - 20
    )
  }
}

// Find resource leaks (fopen without fclose on all paths)
// Allows fclose in the same class (e.g. destructor) or same function
class ResourceLeak extends FunctionCall {
  ResourceLeak() {
    this.getTarget().getName() = "fopen" and
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
