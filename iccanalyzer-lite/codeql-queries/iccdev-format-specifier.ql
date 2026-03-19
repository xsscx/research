/**
 * @name Wrong printf format specifier in Describe/ToXml
 * @description Detects printf-family calls in Describe() and ToXml() methods
 *              where the format string uses incorrect specifiers. Common bugs:
 *              - "%8f" instead of "%.8f" (width vs precision — prints wrong values)
 *              - "%8.f" instead of "%.8f" (width with zero precision)
 *              - "%lf" without explicit precision (prints excessive decimal places)
 *              These are the exact patterns fixed by CFL-053 and CFL-054.
 * @kind problem
 * @id icc/wrong-format-specifier
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @tags correctness
 *       external/cwe/cwe-134
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A Describe(), ToXml(), or DumpLut() method on a CIcc* class.
 */
class IccOutputMethod extends MemberFunction {
  IccOutputMethod() {
    this.getDeclaringType().getName().matches("CIcc%") and
    this.getName().regexpMatch("Describe|ToXml|DumpLut|Dump")
  }
}

/**
 * A printf-family call (sprintf, snprintf, fprintf, printf).
 */
class PrintfCall extends FunctionCall {
  PrintfCall() {
    this.getTarget().getName().regexpMatch("sprintf|snprintf|fprintf|printf|sstream")
  }
}

from IccOutputMethod m, PrintfCall pc, StringLiteral fmt
where
  pc.getEnclosingFunction() = m and
  fmt = pc.getAnArgument() and
  (
    // "%Nf" without dot — width specifier, NOT precision (prints wrong values)
    fmt.getValue().regexpMatch(".*%[0-9]+f.*") and
    not fmt.getValue().regexpMatch(".*%[0-9]+\\.[0-9]+f.*") and
    not fmt.getValue().regexpMatch(".*%-[0-9]+f.*")
    or
    // "%N.f" — dot but no precision digits (defaults to 0 decimal places)
    fmt.getValue().regexpMatch(".*%[0-9]+\\.f.*")
    or
    // "%lf" without explicit precision — prints 6 decimal places by default
    fmt.getValue().regexpMatch(".*%l?f.*") and
    not fmt.getValue().regexpMatch(".*%[0-9]*\\.[0-9]+l?f.*") and
    not fmt.getValue().regexpMatch(".*%-[0-9]*\\.[0-9]+l?f.*")
  )
select pc,
  "Format specifier in " + m.getDeclaringType().getName() + "::" + m.getName() +
    " may produce wrong output: '" + fmt.getValue() +
    "' — check for missing dot (%8f vs %.8f) or missing precision (%lf vs %.4lf) " +
    "(CWE-134, CFL-053/CFL-054 pattern)"
