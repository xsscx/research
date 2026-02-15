/**
 * @name Unvalidated output file path from command-line argument
 * @description Detects file write operations using argv without path traversal validation
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/unvalidated-output-path
 * @tags security
 *       path-traversal
 *       exploit-research
 */

import cpp

from FunctionCall fc, ArrayExpr argv
where
  // File-opening functions used for writing
  (
    fc.getTarget().getName() in ["fopen", "open", "creat"] and
    fc.getArgument(0) = argv
  )
  and
  // argv array access (argv[N] where N >= 2, typically output paths)
  argv.getArrayBase().(VariableAccess).getTarget().getName() = "argv"
  and
  // Exclude iccDEV upstream
  not fc.getFile().toString().matches("%iccDEV%")
select fc, "Output file path from argv passed to " + fc.getTarget().getName() + " without path traversal validation"
