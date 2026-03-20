/// @file IccConformanceV5.h
/// @brief ICC.2-2023 v5/iccMAX conformance checks (CF-080 through CF-089).
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

int RunV5Conformance(CIccProfile *pIcc);

#endif
