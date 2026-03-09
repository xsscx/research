/*
 * IccHeuristicsXmlSafety.h — XML serialization safety heuristics (H142-H145)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * These heuristics extend coverage to the 25 XML-related iccDEV security
 * advisories by exercising the IccLibXML serialization path (ToXml) and
 * validating binary preconditions that trigger XML serializer bugs.
 */

#ifndef ICC_HEURISTICS_XML_SAFETY_H
#define ICC_HEURISTICS_XML_SAFETY_H

#include "IccProfile.h"

// H142: XML Serialization Safety — exercises CIccProfileXml::ToXml() under
// fork() isolation. Any crash/ASAN error during serialization = CRITICAL.
// Covers all 25 XML-related advisories (HBO, SBO, NPD, type confusion, SO).
int RunHeuristic_H142_XmlSerializationSafety(CIccProfile *pIcc, const char *filename);

// H143: XML Array Bounds Precheck — validates array tag element counts match
// available data sizes before serialization. Catches CIccXmlArrayType HBO.
int RunHeuristic_H143_XmlArrayBoundsPrecheck(CIccProfile *pIcc);

// H144: XML String Termination Precheck — validates all string fields are
// null-terminated within fixed-size buffers before ToXml. Catches colorant
// table HBO read patterns.
int RunHeuristic_H144_XmlStringTerminationPrecheck(CIccProfile *pIcc);

// H145: XML Curve Type Consistency — validates curve/MPE type signatures
// match expected element types before ToXmlCurve. Catches type confusion.
int RunHeuristic_H145_XmlCurveTypeConsistency(CIccProfile *pIcc);

#endif // ICC_HEURISTICS_XML_SAFETY_H
