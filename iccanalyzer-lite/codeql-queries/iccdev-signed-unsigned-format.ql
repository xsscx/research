/**
 * @name Signed/unsigned format specifier mismatch
 * @description Detects printf-family calls where %u is used with a signed int
 *              argument, or %d is used with an unsigned type. When the signed
 *              value is negative, %u prints a large positive number — silently
 *              corrupting output and potentially masking loop counter errors.
 *              This is the exact pattern fixed by CFL-055 (fromIt8 %u with signed nColor).
 * @kind problem
 * @id icc/signed-unsigned-format-mismatch
 * @problem.severity warning
 * @security-severity 4.0
 * @precision medium
 * @tags correctness
 *       external/cwe/cwe-681
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A function in ICC code (IccProfLib, IccXML, Tools).
 */
class IccFunction extends Function {
  IccFunction() {
    exists(File f | f = this.getFile() |
      f.getBaseName().matches("Icc%") or
      f.getBaseName().matches("icc%")
    )
  }
}

from FunctionCall fc, int formatArgIdx, int argIdx, Expr formatArg, Expr valueArg
where
  fc.getTarget().getName().regexpMatch("sprintf|snprintf|fprintf|printf") and
  fc.getEnclosingFunction() instanceof IccFunction and
  // Get format string
  formatArg = fc.getArgument(formatArgIdx) and
  formatArg instanceof StringLiteral and
  (
    // %u with signed argument
    formatArg.(StringLiteral).getValue().regexpMatch(".*%[0-9]*u.*") and
    argIdx > formatArgIdx and
    valueArg = fc.getArgument(argIdx) and
    valueArg.getType().getUnspecifiedType() instanceof IntType and
    valueArg.getType().getUnspecifiedType().(IntType).isSigned()
    or
    // %d with unsigned argument
    formatArg.(StringLiteral).getValue().regexpMatch(".*%[0-9]*d.*") and
    argIdx > formatArgIdx and
    valueArg = fc.getArgument(argIdx) and
    valueArg.getType().getUnspecifiedType() instanceof IntType and
    valueArg.getType().getUnspecifiedType().(IntType).isUnsigned()
  )
select fc,
  "Format specifier mismatch in " + fc.getEnclosingFunction().getName() +
    ": signed/unsigned argument type does not match format string — " +
    "negative values print as large positive numbers with %u " +
    "(CWE-681, CFL-055 pattern)"
