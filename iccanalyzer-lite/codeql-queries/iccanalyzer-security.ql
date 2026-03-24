/**
 * @name IccAnalyzer Security Analysis
 * @description Finds potential security issues in IccAnalyzer tool
 * @kind problem
 * @problem.severity warning
 * @id cpp/iccanalyzer-security
 */

import cpp
// Find fread/fwrite calls whose return values are ignored entirely.
class UncheckedFileRead extends FunctionCall {
  UncheckedFileRead() {
    this.getTarget().getName() in ["fread", "fwrite"] and
    this.getFile().getBaseName().matches("IccAnalyzer%") and
    this.getEnclosingStmt() instanceof ExprStmt
  }
}

from UncheckedFileRead call
select call, "Return value from " + call.getTarget().getName() +
             " is ignored. Check the number of bytes processed before trusting the buffer."
