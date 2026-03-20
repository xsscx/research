/// @file IccConformanceSecurity.h
/// @brief Security-oriented conformance checks (CF-091 through CF-094).
#ifndef ICC_CONFORMANCE_SECURITY_H
#define ICC_CONFORMANCE_SECURITY_H

class CIccProfile;

int RunCF091_MalwareSignatureScan(CIccProfile *pIcc, const char *filename);
int RunCF092_PrivateTagPresence(CIccProfile *pIcc);
int RunCF093_PrivateTagContentScan(CIccProfile *pIcc, const char *filename);
int RunCF094_ShellcodePatternScan(const char *filename);

int RunSecurityConformance(CIccProfile *pIcc, const char *filename);

#endif // ICC_CONFORMANCE_SECURITY_H
