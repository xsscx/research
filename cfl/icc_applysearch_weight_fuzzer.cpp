/*
 * Weight-focused variant for CIccCmmSearch.
 *
 * Reuses the main apply-search harness while varying AttachPCC weights across
 * positive, zero, negative, and non-finite cases.  Keep this as a separate
 * binary so the baseline apply-search fuzzer can preserve its stable corpus
 * shape while this target explores denominator validation.
 */

#define ICC_APPLYSEARCH_FUZZ_WEIGHTS 1
#include "icc_applysearch_fuzzer.cpp"
