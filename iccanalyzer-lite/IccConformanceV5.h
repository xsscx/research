/// @file IccConformanceV5.h
/// @brief ICC.2-2023 v5/iccMAX conformance checks (CF-080 through CF-089)
///        plus ICS/Embedding/dictType checks (CF-144 through CF-162).
#ifndef ICC_CONFORMANCE_V5_H
#define ICC_CONFORMANCE_V5_H

class CIccProfile;

int RunCF080_SpectralPCSSignature(CIccProfile *pIcc);
int RunCF081_SpectralPCSRange(CIccProfile *pIcc);
int RunCF082_PCCTagsRequired(CIccProfile *pIcc);
int RunCF083_MCSSignature(CIccProfile *pIcc);
int RunCF084_ProfileSubClass(CIccProfile *pIcc);
int RunCF085_V5VersionBCD(CIccProfile *pIcc);
int RunCF086_ExtendedAttributes(CIccProfile *pIcc);
int RunCF087_MPEElementSignature(CIccProfile *pIcc);
int RunCF088_CalculatorStackStructure(CIccProfile *pIcc);
int RunCF089_SpectralWavelengthRange(CIccProfile *pIcc);
int RunCF115_CalculatorElementComplexityRaw(const char *filename);
int RunCF140_GBDVertexCountFieldRaw(const char *filename);
int RunCF286_GBDTriangleVertexConsistencyRaw(const char *filename);
int RunCF287_GBDChannelPlausibilityRaw(const char *filename);

// ICS Extended Range checks (CF-144..CF-148)
int RunCF144_ExtendedRangePCSFlagConsistency(CIccProfile *pIcc);
int RunCF145_ExtendedRangePCSSpectralCoexistence(CIccProfile *pIcc);
int RunCF146_ExtendedRangeClassRestriction(CIccProfile *pIcc);
int RunCF147_ExtendedRangeColorimetricIntent(CIccProfile *pIcc);
int RunCF148_ExtendedRangeLUTPresence(CIccProfile *pIcc);

// ICS Extended Output checks (CF-149..CF-152)
int RunCF149_ExtendedOutputProfileClass(CIccProfile *pIcc);
int RunCF150_ExtendedOutputGamutTag(CIccProfile *pIcc);
int RunCF151_ExtendedOutputMediaWhitePointRange(CIccProfile *pIcc);
int RunCF152_ExtendedOutputAToBCompleteness(CIccProfile *pIcc);

// ICC.2-in-ICC.1 Embedding checks (CF-153..CF-158)
int RunCF153_EmbeddedProfileTagPresence(CIccProfile *pIcc);
int RunCF154_EmbeddedProfileVersionBridging(CIccProfile *pIcc);
int RunCF155_EmbeddedProfileDeviceClassMatch(CIccProfile *pIcc);
int RunCF156_EmbeddedProfilePCSCompatibility(CIccProfile *pIcc);
int RunCF157_EmbeddedProfileRecursiveDepth(CIccProfile *pIcc);
int RunCF158_EmbeddedProfileSizeBounds(CIccProfile *pIcc);

// dictType Validation checks (CF-159..CF-162)
int RunCF159_DictNameUniqueness(CIccProfile *pIcc);
int RunCF160_DictNameNonZero(CIccProfile *pIcc);
int RunCF161_DictRecordLengthAlignment(CIccProfile *pIcc);
int RunCF162_DictEntryCountBounds(CIccProfile *pIcc);

int RunV5Conformance(CIccProfile *pIcc);

#endif
