/// @file IccConformanceQuality.h
/// @brief Profile quality conformance checks (CF-099 through CF-102).
#ifndef ICC_CONFORMANCE_QUALITY_H
#define ICC_CONFORMANCE_QUALITY_H

class CIccProfile;

int RunCF099_RoundTripDeltaE(CIccProfile *pIcc);
int RunCF100_CurveInvertibility(CIccProfile *pIcc);
int RunCF101_TransformSmoothness(CIccProfile *pIcc);
int RunCF102_CharacterizationRoundTrip(CIccProfile *pIcc);

int RunQualityConformance(CIccProfile *pIcc);

#endif // ICC_CONFORMANCE_QUALITY_H
