/**
 * @name XML External Entity and Network Access Detection
 * @description Detects XML External Entity (XXE) vulnerabilities, unsafe XML parsing,
 *              and potential network access attempts in XML processing code.
 *              Critical for IccFromXml and IccToXml tools which parse untrusted XML.
 * @kind problem
 * @problem.severity error
 * @id icc/xml-external-entity-attacks
 * @tags security xml xxe network-access exploit-research
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

/**
 * XML parsing functions that may be vulnerable to XXE
 */
class XmlParsingFunction extends Function {
  XmlParsingFunction() {
    this.getName().matches([
      "xmlParse%",           // libxml2 parsing functions
      "xmlRead%",            // libxml2 read functions
      "xmlCtxtRead%",        // libxml2 context read
      "xmlSAXParse%",        // SAX parser
      "LoadXml%",            // Custom XML loading (IccFromXml)
      "ParseXml%",           // Custom XML parsing
      "ReadXML%"             // Potential XML read
    ])
  }
}

/**
 * XML parser context creation that may be unsafe
 */
class XmlParserContextCreation extends FunctionCall {
  XmlParserContextCreation() {
    this.getTarget().getName().matches([
      "xmlNewParserCtxt",
      "xmlCreatePushParserCtxt",
      "xmlCreateFileParserCtxt",
      "xmlCreateMemoryParserCtxt",
      "xmlCreateURLParserCtxt"
    ])
  }
}

/**
 * XML parser options that control XXE protection
 */
class XmlParserOptionSet extends FunctionCall {
  XmlParserOptionSet() {
    this.getTarget().getName() = [
      "xmlCtxtUseOptions",
      "xmlSetExternalEntityLoader"
    ]
  }
  
  predicate hasSafeOptions() {
    exists(Expr arg |
      arg = this.getAnArgument() and
      arg.toString().matches([
        "%XML_PARSE_NOENT%",      // Disable entity substitution
        "%XML_PARSE_NONET%",      // Disable network access
        "%XML_PARSE_DTDLOAD%",    // Disable DTD loading
        "%XML_PARSE_DTDATTR%"
      ])
    )
  }
}

/**
 * Network access functions
 */
class NetworkAccessFunction extends Function {
  NetworkAccessFunction() {
    this.getName() = [
      "socket",
      "connect",
      "send", "sendto", "sendmsg",
      "recv", "recvfrom", "recvmsg",
      "curl_easy_perform",
      "curl_easy_init",
      "wget",
      "ftp_connect",
      "http_get", "http_post",
      "xmlNanoHTTPMethod",
      "xmlNanoFTPConnect"
    ]
  }
}

/**
 * File access functions that may be triggered by XXE
 */
class FileAccessFunction extends Function {
  FileAccessFunction() {
    this.getName() = [
      "fopen", "open",
      "freopen",
      "fdopen",
      "xmlFileOpen",
      "xmlCheckFilename"
    ]
  }
}

/**
 * URL/URI parsing functions
 */
class UriParsingFunction extends Function {
  UriParsingFunction() {
    this.getName().matches([
      "xmlParse%URI",
      "xmlBuildURI",
      "xmlNormalizeURIPath",
      "xmlURIEscape%"
    ])
  }
}

/**
 * External entity loader function
 */
class ExternalEntityLoader extends Function {
  ExternalEntityLoader() {
    this.getName() = [
      "xmlLoadExternalEntity",
      "xmlNoNetExternalEntityLoader"
    ]
  }
}

/**
 * Detect XML parsing without XXE protection
 */
class UnsafeXmlParsing extends FunctionCall {
  UnsafeXmlParsing() {
    this.getTarget() instanceof XmlParsingFunction and
    
    // Check if there's NO safe parser context set
    not exists(XmlParserOptionSet opts |
      opts.hasSafeOptions() and
      DataFlow::localExprFlow(opts, this.getQualifier())
    ) and
    // Check if the enclosing function does NOT call xmlSubstituteEntitiesDefault(0)
    not exists(FunctionCall disableCall |
      disableCall.getTarget().hasName("xmlSubstituteEntitiesDefault") and
      disableCall.getEnclosingFunction() = this.getEnclosingFunction()
    )
  }
  
  string getSecurityIssue() {
    result = "Potentially unsafe XML parsing without XXE protection (XML_PARSE_NOENT, XML_PARSE_NONET)"
  }
}

/**
 * Network access in XML context
 */
class NetworkAccessInXmlContext extends FunctionCall {
  NetworkAccessInXmlContext() {
    this.getTarget() instanceof NetworkAccessFunction and
    
    // In a function that processes XML
    exists(Function f | f = this.getEnclosingFunction() |
      f.getName().matches(["%Xml%", "%XML%"]) or
      exists(FunctionCall xmlCall | 
        xmlCall.getEnclosingFunction() = f and
        xmlCall.getTarget() instanceof XmlParsingFunction
      )
    )
  }
  
  string getNetworkType() {
    if this.getTarget().getName().matches("curl%") then
      result = "HTTP/HTTPS via libcurl"
    else if this.getTarget().getName().matches("%ftp%") then
      result = "FTP"
    else if this.getTarget().getName().matches("socket%") or 
            this.getTarget().getName() = ["connect", "send", "recv"] then
      result = "Raw socket"
    else if this.getTarget().getName().matches("xmlNano%") then
      result = "libxml2 built-in network (nanoHTTP/nanoFTP)"
    else
      result = "Network access"
  }
}

/**
 * File access in XML context (potential XXE exploitation)
 */
class FileAccessInXmlContext extends FunctionCall {
  FileAccessInXmlContext() {
    this.getTarget() instanceof FileAccessFunction and
    // Exclude our audited preflight code
    not this.getFile().getBaseName().matches(["ColorBleedPreflight.h"]) and
    
    exists(Function f | f = this.getEnclosingFunction() |
      (
        f.getName().matches(["%Xml%", "%XML%"]) and
        // Exclude preflight validation — it does binary reads, not XML parsing
        not f.getName().matches(["%Preflight%", "%Validate%"])
      )
      or
      exists(FunctionCall xmlCall |
        xmlCall.getEnclosingFunction() = f and
        xmlCall.getTarget() instanceof XmlParsingFunction
      )
    )
  }
  
  predicate hasUserControlledPath() {
    exists(VariableAccess va |
      DataFlow::localExprFlow(va, this.getArgument(0)) and
      va.getTarget().getName().matches(["%filename%", "%path%", "%uri%", "%url%"])
    )
  }
}

/**
 * External entity loader being set
 */
class ExternalEntityLoaderSet extends FunctionCall {
  ExternalEntityLoaderSet() {
    this.getTarget().getName() = "xmlSetExternalEntityLoader"
  }
  
  predicate usesDefaultLoader() {
    // Check if default (unsafe) loader is used
    this.getArgument(0).toString() = "xmlLoadExternalEntity"
  }
  
  predicate usesSafeLoader() {
    // Check if safe (no-network) loader is used
    this.getArgument(0).toString() = "xmlNoNetExternalEntityLoader"
  }
}

/**
 * URI/URL parsing that may indicate external entity reference
 */
class UriParsingInXml extends FunctionCall {
  UriParsingInXml() {
    this.getTarget() instanceof UriParsingFunction
  }
  
  string getUriType() {
    if this.getTarget().getName().matches("%Escape%") then
      result = "URI escaping (potential injection point)"
    else if this.getTarget().getName().matches("%Build%") then
      result = "URI construction (potential injection point)"
    else
      result = "URI parsing"
  }
}

/**
 * libxml2 network functions (nanoHTTP, nanoFTP)
 */
class LibxmlNetworkFunction extends FunctionCall {
  LibxmlNetworkFunction() {
    this.getTarget().getName().matches([
      "xmlNanoHTTP%",
      "xmlNanoFTP%",
      "xmlIOHTTPMatch",
      "xmlIOFTPMatch"
    ])
  }
  
  string getProtocol() {
    if this.getTarget().getName().matches("%HTTP%") then
      result = "HTTP/HTTPS"
    else if this.getTarget().getName().matches("%FTP%") then
      result = "FTP"
    else
      result = "Network protocol"
  }
}

/**
 * String literals that look like external entity declarations
 */
class ExternalEntityDeclaration extends StringLiteral {
  ExternalEntityDeclaration() {
    this.getValue().matches([
      "%<!ENTITY%SYSTEM%",
      "%<!ENTITY%PUBLIC%",
      "%<!DOCTYPE%SYSTEM%",
      "%<!DOCTYPE%PUBLIC%"
    ])
  }
  
  string getEntityType() {
    if this.getValue().matches("%SYSTEM%file://%") then
      result = "File system entity (file://)"
    else if this.getValue().matches("%SYSTEM%http%") then
      result = "HTTP entity"
    else if this.getValue().matches("%SYSTEM%ftp%") then
      result = "FTP entity"
    else if this.getValue().matches("%PUBLIC%") then
      result = "Public entity identifier"
    else
      result = "External entity"
  }
}

from Element location, string message
where
  (
    // Issue 1: Unsafe XML parsing
    exists(UnsafeXmlParsing unsafe |
      location = unsafe and
      message = "[Unsafe XML Parsing] XML parsing without XXE protection: " + unsafe.getTarget().getName() + 
                ". Missing XML_PARSE_NOENT and XML_PARSE_NONET options. " +
                "This allows XML External Entity attacks."
    )
    or
    // Issue 2: Network access in XML context
    exists(NetworkAccessInXmlContext net |
      location = net and
      message = "[Network Access in XML] Network access in XML processing context: " + net.getTarget().getName() + 
                " (" + net.getNetworkType() + "). " +
                "Potential XXE exploitation or SSRF vulnerability."
    )
    or
    // Issue 3: File access in XML context with user-controlled path
    exists(FileAccessInXmlContext fileAccess |
      location = fileAccess and
      fileAccess.hasUserControlledPath() and
      message = "[File Access in XML] File access with potentially user-controlled path in XML context: " + 
                fileAccess.getTarget().getName() + 
                ". Potential XXE file disclosure vulnerability."
    )
    or
    // Issue 4: Default (unsafe) external entity loader
    exists(ExternalEntityLoaderSet loader |
      location = loader and
      loader.usesDefaultLoader() and
      message = "[Unsafe Entity Loader] Default external entity loader set (xmlLoadExternalEntity). " +
                "This enables XXE attacks. Use xmlNoNetExternalEntityLoader instead."
    )
    or
    // Issue 5: URI parsing (potential injection point)
    exists(UriParsingInXml uri |
      location = uri and
      message = "[URI Parsing in XML] URI parsing in XML context: " + uri.getTarget().getName() + 
                " (" + uri.getUriType() + "). " +
                "Potential external entity reference or URL injection."
    )
    or
    // Issue 6: libxml2 network functions
    exists(LibxmlNetworkFunction libnet |
      location = libnet and
      message = "[libxml2 Network Function] libxml2 network function: " + libnet.getTarget().getName() + 
                " (" + libnet.getProtocol() + "). " +
                "Used by XXE for external entity retrieval."
    )
    or
    // Issue 7: External entity declaration in strings
    exists(ExternalEntityDeclaration entity |
      location = entity and
      message = "[External Entity Declaration] External entity declaration in string literal: " + entity.getEntityType() + 
                ". Potential XXE attack vector if processed."
    )
  )
select location, message
