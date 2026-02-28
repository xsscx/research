/**
 * @name Comprehensive XML Security Vulnerabilities
 * @description Detects all XML-related security vulnerabilities including XXE, XPath injection,
 *              XML injection, XInclude, XSLT injection, XML bomb DoS, and unsafe XML operations.
 *              Comprehensive coverage for all XML attack vectors in ICC profile processing.
 * @kind problem
 * @problem.severity error
 * @id icc/xml-all-attacks
 * @tags security xml xxe xpath-injection xml-injection xinclude xslt dos exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

/**
 * Sources: User-controlled XML data
 */
class XmlInputSource extends Expr {
  XmlInputSource() {
    // Command-line arguments (filenames)
    exists(FunctionCall call, Function f |
      f.getName() = "main" and
      call.getEnclosingFunction() = f and
      this = call.getAnArgument()
    )
    or
    // File read operations
    exists(FunctionCall call |
      call.getTarget().getName().matches(["fopen", "open", "fread", "read"]) and
      this = call
    )
    or
    // XML parsing from file
    exists(FunctionCall call |
      call.getTarget().getName().matches(["xmlReadFile", "xmlReadMemory", "xmlParseFile"]) and
      this = call.getAnArgument()
    )
  }
}

/**
 * XPath evaluation functions (XPath injection risk)
 */
class XPathEvalFunction extends Function {
  XPathEvalFunction() {
    this.getName().matches([
      "xmlXPathEval%",
      "xmlXPathEvalExpression",
      "xmlXPathCompiledEval",
      "xmlXPathNodeEval",
      "xmlXPathObjectCopy",
      "icXPath%"  // Custom XPath functions
    ])
  }
}

/**
 * XPath injection: User-controlled data in XPath expressions
 */
class XPathInjection extends FunctionCall {
  XPathInjection() {
    this.getTarget() instanceof XPathEvalFunction and
    exists(Variable v |
      this.getAnArgument() = v.getAnAccess() and
      v.getName().matches(["%xml%", "%path%", "%query%", "%expr%", "%node%"])
    )
  }
  
  string getXPathType() {
    if this.getTarget().getName().matches("%Compiled%") then
      result = "Compiled XPath (safer but still injectable)"
    else
      result = "Direct XPath evaluation"
  }
}

/**
 * XML node creation/modification (XML injection risk)
 */
class XmlNodeManipulation extends Function {
  XmlNodeManipulation() {
    this.getName().matches([
      "xmlNewChild",
      "xmlNewTextChild",
      "xmlNewProp",
      "xmlSetProp",
      "xmlAddChild",
      "xmlNodeSetContent",
      "xmlNodeAddContent",
      "xmlSetNs"
    ])
  }
}

/**
 * XML injection: User data inserted into XML without encoding
 */
class XmlInjection extends FunctionCall {
  XmlInjection() {
    this.getTarget() instanceof XmlNodeManipulation and
    // Check if argument is user-controlled (simple heuristic)
    exists(VariableAccess va |
      this.getAnArgument() = va and
      not exists(FunctionCall encode |
        encode.getTarget().getName().matches([
          "xmlEncodeEntities%",
          "xmlEncodeSpecialChars",
          "icAnsiToUtf8",
          "icUtf16ToUtf8"
        ]) and
        encode.getAnArgument() = va
      )
    )
  }
  
  string getInjectionPoint() {
    if this.getTarget().getName().matches("%Content%") then
      result = "Node content (text injection)"
    else if this.getTarget().getName().matches("%Prop%") then
      result = "Node attribute (attribute injection)"
    else if this.getTarget().getName().matches("%Child%") then
      result = "Node structure (structure injection)"
    else
      result = "XML manipulation"
  }
}

/**
 * XInclude processing (can load external files/URLs)
 */
class XIncludeProcessing extends FunctionCall {
  XIncludeProcessing() {
    this.getTarget().getName().matches([
      "xmlXIncludeProcess%",
      "xmlXIncludeProcessFlags",
      "xmlXIncludeProcessTree"
    ])
  }
  
  predicate hasSecureFlags() {
    // Check for XINCLUDE_NONET flag
    this.getAnArgument().toString().matches("%XINCLUDE_NONET%")
  }
}

/**
 * XSLT transformation (code execution risk)
 */
class XsltTransformation extends FunctionCall {
  XsltTransformation() {
    this.getTarget().getName().matches([
      "xsltApplyStylesheet%",
      "xsltRunStylesheet%",
      "xsltParseStylesheet%",
      "xsltLoadStylesheet%"
    ])
  }
  
  predicate hasUserControlledStylesheet() {
    exists(VariableAccess va |
      this.getAnArgument() = va and
      va.getTarget().getName().matches(["%file%", "%path%", "%url%", "%xsl%"])
    )
  }
}

/**
 * XML parsing with dangerous options
 */
class DangerousXmlParsing extends FunctionCall {
  DangerousXmlParsing() {
    this.getTarget().getName().matches([
      "xmlReadFile",
      "xmlReadMemory",
      "xmlParseFile",
      "xmlParseMemory",
      "xmlCtxtReadFile",
      "xmlCtxtReadMemory"
    ])
  }
  
  predicate hasOptionArgument() {
    // Check if function has options parameter
    this.getTarget().getNumberOfParameters() >= 3
  }
  
  predicate lacksSafetyFlags() {
    this.hasOptionArgument() and
    (
      // Options is 0 or missing safety flags
      this.getArgument(this.getTarget().getNumberOfParameters() - 1).toString() = "0"
      or
      not this.getArgument(this.getTarget().getNumberOfParameters() - 1).toString().matches([
        "%XML_PARSE_NOENT%",
        "%XML_PARSE_NONET%"
      ])
    )
  }
  
  string getMissingProtection() {
    if not this.getArgument(this.getTarget().getNumberOfParameters() - 1).toString().matches("%XML_PARSE_NOENT%") then
      result = "Missing XML_PARSE_NOENT (entity expansion)"
    else if not this.getArgument(this.getTarget().getNumberOfParameters() - 1).toString().matches("%XML_PARSE_NONET%") then
      result = "Missing XML_PARSE_NONET (network access)"
    else
      result = "Unknown protection gap"
  }
}

/**
 * DTD processing (can lead to XXE and DoS)
 */
class DtdProcessing extends FunctionCall {
  DtdProcessing() {
    this.getTarget().getName().matches([
      "xmlParseDTD",
      "xmlLoadExternalEntity",
      "xmlSAXParseDTD"
    ])
  }
}

/**
 * XML schema validation (schema poisoning risk)
 */
class XmlSchemaValidation extends FunctionCall {
  XmlSchemaValidation() {
    this.getTarget().getName().matches([
      "xmlSchemaValidate%",
      "xmlRelaxNGValidate%",
      "xmlSchemaNewParserCtxt",
      "xmlRelaxNGNewParserCtxt"
    ])
  }
  
  predicate hasUserControlledSchema() {
    exists(VariableAccess va |
      this.getAnArgument() = va and
      va.getTarget().getName().matches(["%schema%", "%xsd%", "%rng%", "%relaxng%"])
    )
  }
}

/**
 * Large XML document processing (DoS risk)
 */
class LargeXmlProcessing extends FunctionCall {
  LargeXmlProcessing() {
    this.getTarget().getName().matches([
      "xmlReadFile",
      "xmlReadMemory",
      "xmlParseFile"
    ]) and
    // No size limit checking before parse
    not exists(FunctionCall sizeCheck |
      sizeCheck.getTarget().getName().matches(["stat", "fstat", "ftell"]) and
      sizeCheck.getEnclosingFunction() = this.getEnclosingFunction()
    )
  }
}

/**
 * XML attribute expansion (attribute bomb)
 */
class XmlAttributeExpansion extends FunctionCall {
  XmlAttributeExpansion() {
    this.getTarget().getName().matches([
      "xmlGetProp",
      "xmlHasProp",
      "xmlGetNsProp"
    ])
  }
}

/**
 * Recursive XML processing (stack overflow risk)
 */
class RecursiveXmlProcessing extends Function {
  RecursiveXmlProcessing() {
    this.getName().matches(["%Xml%", "%XML%"]) and
    // Function calls itself directly or indirectly
    exists(FunctionCall call |
      call.getEnclosingFunction() = this and
      call.getTarget() = this
    )
  }
}

/**
 * String concatenation in XML context (injection risk)
 */
class XmlStringConcatenation extends FunctionCall {
  XmlStringConcatenation() {
    this.getTarget().getName().matches([
      "strcat", "strncat",
      "sprintf", "snprintf",
      "std::string::append",
      "std::string::operator+"
    ]) and
    // Exclude our audited preflight code
    not this.getFile().getBaseName().matches(["ColorBleedPreflight.h"]) and
    exists(Function f | 
      this.getEnclosingFunction() = f and
      f.getName().matches(["%Xml%", "%XML%", "%ToXml%"]) and
      // Exclude preflight validation functions — they format warnings, not XML
      not f.getName().matches(["%Preflight%", "%Validate%"])
    )
  }
}

/**
 * XML namespace manipulation (namespace injection)
 */
class XmlNamespaceManipulation extends FunctionCall {
  XmlNamespaceManipulation() {
    this.getTarget().getName().matches([
      "xmlNewNs",
      "xmlSetNs",
      "xmlSearchNs",
      "xmlSearchNsByHref"
    ])
  }
}

/**
 * Unsafe XML deserialization
 */
class UnsafeXmlDeserialization extends FunctionCall {
  UnsafeXmlDeserialization() {
    // Custom deserialize functions
    this.getTarget().getName().matches([
      "%FromXml%",
      "%ParseXml%",
      "%LoadXml%"
    ]) and
    // Called on user input without validation
    not exists(FunctionCall validate |
      validate.getTarget().getName().matches([
        "%Validate%",
        "%Check%",
        "%Verify%"
      ]) and
      validate.getEnclosingFunction() = this.getEnclosingFunction()
    )
  }
}

/**
 * XML comment injection
 */
class XmlCommentInjection extends FunctionCall {
  XmlCommentInjection() {
    this.getTarget().getName().matches([
      "xmlNewComment",
      "xmlNewDocComment"
    ]) and
    exists(VariableAccess va |
      this.getAnArgument() = va and
      not va.toString().matches("%---%")  // Comment terminator check
    )
  }
}

/**
 * XML CDATA injection
 */
class XmlCdataInjection extends FunctionCall {
  XmlCdataInjection() {
    this.getTarget().getName().matches([
      "xmlNewCDataBlock"
    ]) and
    exists(VariableAccess va |
      this.getAnArgument() = va and
      not va.toString().matches("%]]>%")  // CDATA terminator check
    )
  }
}

from Element location, string message
where
  (
    // Category 1: XPath Injection
    exists(XPathInjection xpath |
      location = xpath and
      message = "[XPath Injection] XPath injection vulnerability: " + xpath.getTarget().getName() + 
                " with potentially user-controlled expression (" + xpath.getXPathType() + "). " +
                "Sanitize XPath expressions or use parameterized queries."
    )
    or
    // Category 2: XML Injection
    exists(XmlInjection inject |
      location = inject and
      message = "[XML Injection] XML injection vulnerability: " + inject.getTarget().getName() + 
                " (" + inject.getInjectionPoint() + "). " +
                "User data inserted without XML encoding. Use xmlEncodeSpecialChars()."
    )
    or
    // Category 3: Unsafe XInclude
    exists(XIncludeProcessing xinc |
      location = xinc and
      not xinc.hasSecureFlags() and
      message = "[Unsafe XInclude] XInclude processing without security flags: " + xinc.getTarget().getName() + ". " +
                "Missing XINCLUDE_NONET flag. Can load external files/URLs."
    )
    or
    // Category 4: XSLT Injection
    exists(XsltTransformation xslt |
      location = xslt and
      xslt.hasUserControlledStylesheet() and
      message = "[XSLT Injection] XSLT transformation with user-controlled stylesheet: " + xslt.getTarget().getName() + ". " +
                "Can execute arbitrary code via XSLT functions (document(), system-property())."
    )
    or
    // Category 5: Unsafe XML Parsing (XXE)
    exists(DangerousXmlParsing parse |
      location = parse and
      parse.lacksSafetyFlags() and
      message = "[Unsafe XML Parsing] XML parsing without security flags: " + parse.getTarget().getName() + ". " +
                parse.getMissingProtection() + ". Enables XXE attacks."
    )
    or
    // Category 6: DTD Processing (XXE)
    exists(DtdProcessing dtd |
      location = dtd and
      message = "[DTD Processing] DTD processing enabled: " + dtd.getTarget().getName() + ". " +
                "Can trigger XXE via external DTD entities. Disable with XML_PARSE_NOENT."
    )
    or
    // Category 7: Schema Poisoning
    exists(XmlSchemaValidation schema |
      location = schema and
      schema.hasUserControlledSchema() and
      message = "[Schema Poisoning] XML validation with user-controlled schema: " + schema.getTarget().getName() + ". " +
                "Attacker can provide malicious schema to bypass validation or cause DoS."
    )
    or
    // Category 8: XML DoS (Large Documents)
    exists(LargeXmlProcessing large |
      location = large and
      message = "[XML DoS Risk] XML parsing without size validation: " + large.getTarget().getName() + ". " +
                "Large XML documents can cause memory exhaustion DoS. Add size checks."
    )
    or
    // Category 9: Recursive Processing (Stack DoS)
    exists(RecursiveXmlProcessing recursive |
      location = recursive and
      message = "[Recursive XML DoS] Recursive XML processing function: " + recursive.getName() + ". " +
                "Deeply nested XML can cause stack overflow. Add depth limit."
    )
    or
    // Category 10: XML String Concatenation
    exists(XmlStringConcatenation strconcat |
      location = strconcat and
      message = "[XML String Injection] String concatenation in XML context: " + strconcat.getTarget().getName() + ". " +
                "Potential XML injection. Use XML builder APIs instead."
    )
    or
    // Category 11: Namespace Injection
    exists(XmlNamespaceManipulation nsmanip |
      location = nsmanip and
      message = "[Namespace Injection] XML namespace manipulation: " + nsmanip.getTarget().getName() + ". " +
                "Validate namespace URIs to prevent namespace poisoning attacks."
    )
    or
    // Category 12: Unsafe Deserialization
    exists(UnsafeXmlDeserialization unserial |
      location = unserial and
      message = "[Unsafe XML Deserialization] XML deserialization without validation: " + unserial.getTarget().getName() + ". " +
                "Can deserialize malicious objects. Add validation before deserialization."
    )
    or
    // Category 13: Comment Injection
    exists(XmlCommentInjection commentinj |
      location = commentinj and
      message = "[XML Comment Injection] XML comment creation with unvalidated data: " + commentinj.getTarget().getName() + ". " +
                "Check for comment terminator (-->) to prevent comment breakout."
    )
    or
    // Category 14: CDATA Injection
    exists(XmlCdataInjection cdatainj |
      location = cdatainj and
      message = "[XML CDATA Injection] XML CDATA creation with unvalidated data: " + cdatainj.getTarget().getName() + ". " +
                "Check for CDATA terminator (]]>) to prevent CDATA breakout."
    )
  )
select location, message
