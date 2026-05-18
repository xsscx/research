/**
 * @name IccDumpProfile Tool - Enum UB Reachability Analysis
 * @description Identifies enum undefined behavior issues reachable via IccDumpProfile tool
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/iccdumpprofile-enum-ub-reachability
 * @tags security
 *       reachability
 *       tool-specific
 *       enum-ub
 */

import cpp

/**
 * The IccDumpProfile main function
 */
class IccDumpProfileMain extends Function {
  IccDumpProfileMain() {
    this.getName() = "main" and
    this.getFile().getBaseName() = "iccDumpProfile.cpp"
  }
}

/**
 * Functions called from IccDumpProfile tool
 */
class IccDumpProfileReachable extends Function {
  IccDumpProfileReachable() {
    exists(IccDumpProfileMain main |
      // Direct calls from main
      main.calls(this)
      or
      // Transitive calls (up to 10 levels deep)
      exists(Function intermediate |
        main.calls+(intermediate) and
        intermediate.calls(this)
      )
    )
    or
    // Key entry points called by IccDumpProfile
    this.getName() in [
      "OpenIccProfile",
      "ValidateIccProfile",
      "FindTag",
      "LoadTag",
      "DumpTagEntry",
      "DumpTagSig",
      "DumpTagCore",
      "GetColorSpaceSigName",
      "GetRenderingIntentName",
      "GetProfileClassSigName",
      "GetCmmSigName",
      "GetPlatformSigName",
      "GetDeviceAttrName",
      "GetProfileFlagsName"
    ]
  }
}

/**
 * Enum variable with potentially invalid value
 */
class PotentiallyInvalidEnumVar extends Variable {
  PotentiallyInvalidEnumVar() {
    this.getType().getUnspecifiedType() instanceof Enum and
    exists(FunctionCall readCall |
      // Variable is loaded from Read operation
      readCall.getTarget().getName().matches("%Read%") and
      readCall.getAnArgument().(AddressOfExpr).getOperand() = this.getAnAccess()
    )
  }
  
  Enum getEnumType() {
    result = this.getType().getUnspecifiedType()
  }
}

/**
 * Comparison on enum variable that may have invalid value
 */
class EnumComparisonInReachableCode extends ComparisonOperation {
  EnumComparisonInReachableCode() {
    exists(PotentiallyInvalidEnumVar enumVar |
      (
        this.getLeftOperand() = enumVar.getAnAccess() or
        this.getRightOperand() = enumVar.getAnAccess()
      ) and
      // Occurs in function reachable from IccDumpProfile
      exists(IccDumpProfileReachable func |
        this.getEnclosingFunction() = func
      )
    )
  }
  
  PotentiallyInvalidEnumVar getEnumVar() {
    this.getLeftOperand() = result.getAnAccess() or
    this.getRightOperand() = result.getAnAccess()
  }
}

/**
 * Access to header fields used by IccDumpProfile
 */
class HeaderFieldAccess extends FieldAccess {
  HeaderFieldAccess() {
    // Fields accessed in IccDumpProfile main (lines 237-249)
    exists(IccDumpProfileMain main |
      this.getEnclosingFunction() = main and
      this.getTarget().getName() in [
        "colorSpace",      // line 244: pHdr->colorSpace
        "pcs",             // line 246: pHdr->pcs  
        "renderingIntent", // line 248: pHdr->renderingIntent
        "deviceClass",     // line 249: pHdr->deviceClass
        "cmmId",           // line 238: pHdr->cmmId
        "platform",        // line 247: pHdr->platform
        "attributes",      // line 237: pHdr->attributes
        "flags"            // line 245: pHdr->flags
      ]
    )
  }
}

/**
 * CIccInfo formatting functions called by IccDumpProfile
 */
class IccInfoFormatterCall extends FunctionCall {
  IccInfoFormatterCall() {
    exists(IccDumpProfileMain main |
      this.getEnclosingFunction() = main and
      this.getTarget().getName() in [
        "GetColorSpaceSigName",     // Called at lines 244, 246
        "GetRenderingIntentName",   // Called at line 248
        "GetProfileClassSigName",   // Called at line 249
        "GetCmmSigName",            // Called at line 238
        "GetPlatformSigName",       // Called at line 247
        "GetDeviceAttrName",        // Called at line 237
        "GetProfileFlagsName"       // Called at line 245
      ]
    )
  }
}

/**
 * Tag iteration in IccDumpProfile
 */
class TagIterationLoop extends Loop {
  TagIterationLoop() {
    exists(IccDumpProfileMain main |
      this.getEnclosingFunction() = main and
      // Loop over profile tags
      exists(VariableAccess va |
        va.getTarget().getName() = "i" and
        this.getStmt().getAChild*() = va
      )
    )
  }
}

from EnumComparisonInReachableCode comp, PotentiallyInvalidEnumVar enumVar, 
     IccDumpProfileReachable func, string message, string toolPath
where
  enumVar = comp.getEnumVar() and
  func = comp.getEnclosingFunction() and
  message = "REACHABLE via IccDumpProfile: Enum comparison on potentially invalid value. " +
            "Enum type: " + enumVar.getEnumType().getName() + ". " +
            "Function: " + func.getName() + ". " +
            "This vulnerability is triggered when IccDumpProfile parses a malformed ICC profile." and
  toolPath = "Tools/CmdLine/IccDumpProfile/iccDumpProfile.cpp"
select comp, message, enumVar, "Enum variable: " + enumVar.getName(), func, "Reachable function: " + func.getName()
