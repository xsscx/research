/**
 * @name Unchecked return value from I/O function
 * @description Finds calls to fread/fwrite where return value is not checked
 * @kind problem
 * @problem.severity error
 * @id cpp/unchecked-io-return
 * @tags security
 *       reliability
 */

import cpp

from FunctionCall fc
where fc.getTarget().getName() in ["fread", "fwrite"]
  and fc.getFile().toString().matches("%iccAnalyzer.cpp")
  and not exists(BinaryOperation cmp |
    cmp.getAnOperand() = fc or
    cmp.getAnOperand().(VariableAccess).getTarget().getAnAssignedValue() = fc
  )
select fc, "Return value from " + fc.getTarget().getName() + " is not checked"
