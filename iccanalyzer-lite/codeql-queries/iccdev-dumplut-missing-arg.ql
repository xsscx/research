/**
 * @name DumpLut/Iterate call missing boolean argument
 * @description Detects calls to DumpLut() or Iterate() where the call has
 *              fewer arguments than the function's parameter list. In iccDEV,
 *              the DumpLut() 6th parameter and Iterate() 5th parameter control
 *              legacy encoding behavior (bUseLegacy). Omitting it causes the
 *              compiler to pass garbage or a default-constructed value, producing
 *              wrong LUT output or silent data corruption.
 *              CFL-048: Iterate() called with bool bUseLegacy as bufSize param.
 *              CFL-049: BToA DumpLut() missing bUseLegacy argument entirely.
 * @kind problem
 * @id icc/dumplut-missing-arg
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @tags correctness
 *       external/cwe/cwe-131
 *       external/cwe/cwe-688
 *       iccdev
 *       maintainer
 */

import cpp

/**
 * A DumpLut or Iterate method that takes a boolean bUseLegacy parameter.
 */
class LutDumpMethod extends MemberFunction {
  LutDumpMethod() {
    this.getDeclaringType().getName().matches("CIcc%") and
    this.getName().regexpMatch("DumpLut|Iterate") and
    exists(Parameter p | p = this.getAParameter() |
      p.getType() instanceof BoolType or
      p.getName().matches("%Legacy%") or
      p.getName().matches("%legacy%")
    )
  }
}

from FunctionCall fc, LutDumpMethod target
where
  fc.getTarget() = target and
  // Call has fewer arguments than the method's parameter count
  fc.getNumberOfArguments() < target.getNumberOfParameters() and
  // In ICC code
  exists(File f | f = fc.getFile() |
    f.getBaseName().matches("Icc%") or
    f.getBaseName().matches("icc%")
  )
select fc,
  "Call to " + target.getDeclaringType().getName() + "::" + target.getName() +
    " passes " + fc.getNumberOfArguments().toString() + " arguments but " +
    "method expects " + target.getNumberOfParameters().toString() +
    " — missing bUseLegacy or bufSize parameter causes wrong LUT output " +
    "(CWE-131, CFL-048/CFL-049 pattern)"
