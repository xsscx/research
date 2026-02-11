/**
 * @name All Tools - Enum UB Reachability Analysis
 * @description Identifies enum UB issues reachable from ALL project tools
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/all-tools-enum-ub-reachability
 * @tags security
 *       reachability
 *       multi-tool-analysis
 *       enum-ub
 */

import cpp

/**
 * Main function of any project tool
 */
class ToolMain extends Function {
  string toolName;
  
  ToolMain() {
    this.getName() = "main" and
    exists(string filename |
      filename = this.getFile().getBaseName() and
      (
        // Core ICC tools
        (filename = "iccDumpProfile.cpp" and toolName = "IccDumpProfile") or
        (filename = "iccRoundTrip.cpp" and toolName = "IccRoundTrip") or
        (filename = "iccApplyNamedCmm.cpp" and toolName = "IccApplyNamedCmm") or
        (filename = "iccApplySearch.cpp" and toolName = "IccApplySearch") or
        (filename = "iccApplyToLink.cpp" and toolName = "IccApplyToLink") or
        (filename = "IccV5DspObsToV4Dsp.cpp" and toolName = "IccV5DspObsToV4Dsp") or
        (filename = "iccSpecSepToTiff.cpp" and toolName = "IccSpecSepToTiff") or
        (filename = "iccFromCube.cpp" and toolName = "IccFromCube") or
        
        // Image dump tools
        (filename = "iccTiffDump.cpp" and toolName = "IccTiffDump") or
        (filename = "iccJpegDump.cpp" and toolName = "IccJpegDump") or
        (filename = "iccPngDump.cpp" and toolName = "IccPngDump") or
        
        // XML tools
        (filename = "IccToXml.cpp" and toolName = "IccToXml") or
        (filename = "IccFromXml.cpp" and toolName = "IccFromXml") or
        
        // IccApplyProfiles (has different structure)
        (filename.matches("iccApply%") and toolName = "IccApplyProfiles")
      )
    )
  }
  
  string getToolName() { result = toolName }
}

/**
 * Functions reachable from any tool
 */
class ToolReachable extends Function {
  ToolMain tool;
  
  ToolReachable() {
    exists(ToolMain main |
      tool = main and
      (
        // Direct calls from main
        main.calls(this)
        or
        // Transitive calls (up to 15 levels for deep call chains)
        exists(Function intermediate |
          main.calls+(intermediate) and
          intermediate.calls(this)
        )
      )
    )
    or
    // Common ICC library functions called by all tools
    this.getName() in [
      "OpenIccProfile",
      "ValidateIccProfile", 
      "ReadIccProfile",
      "CIccProfile",
      "Read",
      "FindTag",
      "LoadTag",
      "GetType",
      "Validate",
      "CheckHeader",
      "CheckRequiredTags",
      "CheckTagExclusion",
      "EvaluateProfile",
      "Apply",
      "GetXform",
      "Begin",
      "SetSrcSpace",
      "SetDestSpace",
      "GetColorSpaceSigName",
      "GetRenderingIntentName"
    ]
  }
  
  ToolMain getReachableFromTool() { result = tool }
}

/**
 * Enum variable loaded from untrusted source
 */
class UntrustedEnumVar extends Variable {
  UntrustedEnumVar() {
    this.getType().getUnspecifiedType() instanceof Enum and
    exists(FunctionCall readCall |
      readCall.getTarget().getName().matches("%Read%") and
      readCall.getAnArgument().(AddressOfExpr).getOperand() = this.getAnAccess()
    )
  }
  
  Enum getEnumType() {
    result = this.getType().getUnspecifiedType()
  }
}

/**
 * Enum comparison in tool-reachable code
 */
class ToolReachableEnumComparison extends ComparisonOperation {
  UntrustedEnumVar enumVar;
  ToolReachable func;
  
  ToolReachableEnumComparison() {
    enumVar.getAnAccess() = this.getAnOperand() and
    this.getEnclosingFunction() = func
  }
  
  UntrustedEnumVar getEnumVar() { result = enumVar }
  ToolReachable getReachableFunc() { result = func }
  
  /**
   * Get all tools that can reach this comparison
   */
  string getReachableTools() {
    result = concat(ToolMain tool |
      exists(ToolReachable f |
        f = this.getReachableFunc() and
        f.getReachableFromTool() = tool
      ) |
      tool.getToolName(),
      ", "
      order by tool.getToolName()
    )
  }
  
  /**
   * Count how many tools can reach this
   */
  int getToolCount() {
    result = count(ToolMain tool |
      exists(ToolReachable f |
        f = this.getReachableFunc() and
        f.getReachableFromTool() = tool
      )
    )
  }
}

from ToolReachableEnumComparison comp, UntrustedEnumVar enumVar,
     ToolReachable func, string message, string tools, int toolCount
where
  enumVar = comp.getEnumVar() and
  func = comp.getReachableFunc() and
  tools = comp.getReachableTools() and
  toolCount = comp.getToolCount() and
  message = "REACHABLE from " + toolCount.toString() + " tool(s): " + tools + ". " +
            "Enum type: " + enumVar.getEnumType().getName() + ". " +
            "Function: " + func.getName() + ". " +
            "This vulnerability is triggered when tools parse malformed ICC profiles."
select comp, message, enumVar, "Enum: " + enumVar.getName(), func, "Function: " + func.getName()
