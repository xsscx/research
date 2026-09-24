# Incident: Cumulative Parser Review Failure on iccDEV PR #2669

Date: 2026-09-22

## Summary

InternationalColorConsortium/iccDEV#2669 entered Cloud review after a local
pre-PR review concluded that no further parser change was required. The first
Cloud review identified two valid malformed-input cases. A repair was pushed in
`9d438d26`, after focused local validation and a further local review.

The next Cloud review, `5279356725`, then reported two more valid cases as
"Previously missed": entity-reference children in an otherwise empty
`multiLocalizedUnicodeType`, and missing or empty `ProfileIdDesc@id` values.
Those findings were present in unchanged code and had no inline review
threads; they existed only in the review body. They were repaired in
`3a2067a8` after explicit user direction to treat them as first-review items.

The repairs are technically correct. The review process was not. The PR
reached a third submitted change set because the local review treated each
reported condition as a line-local case instead of deriving and checking the
complete XML parser contract before the first repair push.

## Evidence

1. **Local pre-PR screening:** Before Cloud review, concluded no additional
   parser change was needed, but did not record a complete malformed-input
   state matrix.
2. **First Cloud review:** `5278700739` on `574a158d` found acceptance of
   non-whitespace direct text or CDATA in empty `mluc` placeholders and
   truncation of oversized Profile IDs.
3. **First repair push:** `9d438d26` added direct-text, CDATA, whitespace,
   short-ID, and oversized-ID coverage, plus secure fixture writes.
4. **Subsequent local review:** Before the next review result, validated the
   named repair but did not perform a cumulative audit of absent attributes or
   XML entity-reference node types.
5. **Second Cloud review:** `5279356725` on `9d438d26` reported
   entity-reference children and missing or empty IDs as "Previously missed"
   findings in the review body.
6. **Completion repair push:** `3a2067a8` rejected entity-reference children
   and absent or empty IDs; added focused regressions.

Both review-body findings were independently verified:

1. `CIccProfileXml::LoadXml()` deliberately omits `XML_PARSE_NOENT`, so an
   internal DTD entity can remain an `XML_ENTITY_REF_NODE`. The placeholder
   helper treated that node as empty and could silently discard it.
2. `CIccTagXmlProfileSequenceId::ParseXml()` only validated `id` when it was
   non-null and nonempty. Missing and empty attributes retained the default
   zero Profile ID and later serialized as a valid-looking 32-digit value.

## Impact

- The PR consumed another Cloud review to discover parser input states that
  belonged in local preparation.
- The user had to correct the review-cycle classification to permit the
  completion repair.
- Review evidence overstated readiness by listing successful focused commands
  without proving the full parser acceptance and rejection contract.
- The branch received serial repair commits instead of one cumulative
  first-review repair.

## Root Causes

1. The pre-PR review began from the intended happy path and named malformed
   examples, not from a total state model for each parser field.
2. The first repair audit expanded only around the two named review comments.
   It did not enumerate every libxml2 node type that can remain when entity
   substitution is disabled.
3. Fixed-width ID validation was modeled as byte-content validation but not as
   an attribute-presence contract. Missing, empty, malformed, undersized,
   exact-size, and oversized values were not all represented together.
4. Review-body findings without inline threads were not treated as mandatory
   cumulative-review inputs before claiming the repair was complete.
5. Existing readiness rules required one coherent first-cycle repair, but the
   process relied on memory and local interpretation rather than a recorded,
   fail-closed parser contract matrix.

## Required Corrective Control

Before an XML parser review is reported complete or a repair is pushed, record
and test the complete input-state matrix for every changed field:

### Empty `multiLocalizedUnicodeType` placeholder

- **Accepted:** no children, formatting-only whitespace, and documented
  comment handling.
- **Rejected:** elements, non-whitespace text, CDATA, entity references, and
  every non-placeholder semantic node type.
- **Evidence:** one regression per node class for both manufacturer and model
  paths, plus the `LoadXml()` parser-option rationale.

### `ProfileIdDesc@id`

- **Accepted:** present, valid hexadecimal encoding of exactly 16 bytes.
- **Rejected:** missing, empty, malformed, odd-length, short, and oversized
  encodings.
- **Evidence:** one negative regression per state and one exact-size round
  trip.

### Review inventory

- **Accepted:** every inline thread and every review-body or suppressed finding
  has a disposition.
- **Rejected:** a missing review ID, undispositioned summary item, or unknown
  exact reviewed SHA.
- **Evidence:** review-repair ledger tied to the proposed push SHA.

The matrix must be derived before selecting a repair, not extended after a
review service supplies another example. A named finding identifies a contract
class; it does not limit the local audit to that line or literal input.

For every repair push, the ledger must include the base SHA, reviewed SHA,
proposed SHA, all review IDs, all inline and review-body findings, changed
files, the complete state matrix, and commands executed after the latest
edit. If any item is absent, the push is blocked.

If a later automated review is explicitly reclassified by the user as part of
the first review, that direction permits one branch repair but does not waive
the cumulative audit. The next action remains a complete contract review, not
another narrow response to the newly supplied example.

## Decision

Passing focused builds, sanitizer checks, static analysis, and CodeQL queries
does not establish parser-review completeness without the corresponding
acceptance and rejection matrix. Future XML parser repair work must prove that
matrix locally before any review request or repair push. A review-body finding
with no inline thread is a first-class finding and must be included in the
same evidence record.
