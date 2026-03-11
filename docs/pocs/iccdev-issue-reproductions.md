# iccDEV Issue Reproductions

Proof-of-concept reproduction steps for closed security issues in
[InternationalColorConsortium/iccDEV](https://github.com/InternationalColorConsortium/iccDEV).

Each entry provides the exact commands to reproduce the issue. All commands
assume iccDEV is built with ASAN+UBSAN (see [build instructions](../iccDEV/shell-helpers/unix.md)).

> **Generated**: 2026-03-09 from closed issues #480–#656
> **Total**: 63 reproductions across 9 iccDEV tools

## Summary

| Bug Type | Count | CWE |
|----------|-------|-----|
| Undefined Behavior | 20 | CWE-758 |
| Heap Buffer Overflow | 14 | CWE-122 |
| Stack Buffer Overflow | 6 | CWE-121 |
| Null Pointer Deref | 6 | CWE-476 |
| SEGV / Null Deref | 4 | CWE-476 |
| Type Confusion | 3 | CWE-843 |
| Stack Overflow | 2 | CWE-674 |
| Use After Free | 2 | CWE-416 |
| Signed Integer Overflow | 2 | CWE-190 |
| Out of Memory | 2 | CWE-400 |
| Memcpy Overlap | 1 | CWE-119 |
| Out of Bounds Read | 1 | CWE-125 |

| Tool | Reproductions |
|------|---------------|
| `iccFromXml` | 14 |
| `iccApplyProfiles` | 10 |
| `iccDumpProfile` | 9 |
| `iccToXml` | 8 |
| `iccRoundTrip` | 8 |
| `iccApplyNamedCmm` | 6 |
| `iccTiffDump` | 4 |
| `iccV5DspObsToV4Dsp` | 3 |
| `iccFromCube` | 1 |

---

## iccDumpProfile

### #629 — SO: SO in CIccBasicStructFactory::CreateStruct() at IccStructFactory.cpp:93

CWE-674 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/629) · Fix: [PR#630](https://github.com/InternationalColorConsortium/iccDEV/pull/630)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/so-CIccBasicStructFactory-CreateStruct-IccStructFactory_cpp-Line93.icc
# Step 2
iccDumpProfile -v so-CIccBasicStructFactory-CreateStruct-IccStructFactory_cpp-Line93.icc
```

### #568 — OOM: OOM in CIccTagGamutBoundaryDesc::Read() at IccTagLut.cpp:5631

CWE-400 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/568) · Fix: [PR#572](https://github.com/InternationalColorConsortium/iccDEV/pull/572)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc
# Step 2
iccDumpProfile -v oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc
```

### #560 — NPD: NPD in CIccTagUtf16Text::GetBuffer() at IccTagBasic.cpp#L1866

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/560)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/ub-runtime-errorapplying-non-zero-offset-IccTagBasic_cpp-Line1866.icc
# Step 2
iccDumpProfile -v ub-runtime-errorapplying-non-zero-offset-IccTagBasic_cpp-Line1866.icc
```

### #553 — NPD: NPD in CIccTagUtf16Text::GetBuffer() at IccTagBasic.cpp#L1866

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/553)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/blob/master/graphics/icc/ub-runtime-errorapplying-non-zero-offset-IccTagBasic_cpp-Line1866.icc
# Step 2
iccDumpProfile -v ub-runtime-error-apply-non-zero-offset-IccTagBasic_cpp-Line1866.icc
```

### #490 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:2237

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/490)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
# Step 2
iccDumpProfile -v ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
```

### #489 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:2222

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/489)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
# Step 2
iccFromXml ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc oops.icc
```

### #488 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:1834

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/488)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
# Step 2
iccFromXml ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc oops.icc
```

### #487 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:1816

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/487)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
# Step 2
iccFromXml ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc oops.icc
```

### #486 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:1825

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/486)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc
# Step 2
iccFromXml ub-runtime-error-load-value-type-confusion-IccMpeCalc_cpp-Line1825.icc oops.icc
```

---

## iccToXml

### #628 — SO: SO in CIccStructCreator::DoCreateStruct() at IccStructFactory.cpp:191

CWE-843 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/628)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/CIccTagStruct-Read-recursive-stack-overflow.icc
# Step 2
iccToXml CIccTagStruct-Read-recursive-stack-overflow.icc foo.bar
```

### #627 — HBO: HBO in CIccXmlArrayType<> at IccUtilXml.cpp:869

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/627) · Fix: [PR#631](https://github.com/InternationalColorConsortium/iccDEV/pull/631)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccXmlArrayType-icTagTypeSignature-IccUtilXml_cpp-Line869.icc
# Step 2
iccToXml hbo-CIccXmlArrayType-icTagTypeSignature-IccUtilXml_cpp-Line869.icc foo.bar
```

### #624 — SBO: SBO in icFixXml() at IccUtilXml.cpp:314

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/624) · Fix: [PR#634](https://github.com/InternationalColorConsortium/iccDEV/pull/634)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/sbo-icFixXml-IccUtilXml_cpp-Line314.icc
# Step 2
iccToXml sbo-icFixXml-IccUtilXml_cpp-Line314.icc foo.bar
```

### #599 — SIO: UB SIO in CIccTagGamutBoundaryDesc::Read()

CWE-190 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/599)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/ub-runtime-error-signed-integer-overflowIccTagLut_cpp-Line5638.icc
# Step 2
iccToXml ub-runtime-error-signed-integer-overflowIccTagLut_cpp-Line5638.icc foo.bar
```

### #537 — SBO: stack-buffer-overflow in icFixXml() at IccLibXML/IccUtilXml.cpp#L333

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/537) · Fix: [PR#545](https://github.com/InternationalColorConsortium/iccDEV/pull/545)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/stack-buffer-overflow-icFixXml-CIccTagXmlNamedColor2-ToXml-IccUtilXml_cpp-Line333.icc
# Step 2
iccToXml stack-buffer-overflow-icFixXml-CIccTagXmlNamedColor2-ToXml-IccUtilXml_cpp-Line333.icc foo.xml
```

### #499 — UB: UB runtime error: downcast .. does not point to an object of type .. at IccLibXML/IccTagXml.cpp:3094

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/499) · Fix: [PR#516](https://github.com/InternationalColorConsortium/iccDEV/pull/516)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/undefined-behavior-type-confusion-runtime-error-CIccSegmentedCurveXmlIccLibXML-IccTagXml_cpp-Line3094.icc
# Step 2
iccToXml undefined-behavior-type-confusion-runtime-error-CIccSegmentedCurveXmlIccLibXML-IccTagXml_cpp-Line3094.icc oops.xml
```

### #492 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:2993

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/492)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-load-of-value-not-valid-IccMpeCalc_cpp-Line3029.icc
# Step 2
iccToXml ub-load-of-value-not-valid-IccMpeCalc_cpp-Line3029.icc oops.icc
```

### #491 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:3029

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/491)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-load-of-value-not-valid-IccMpeCalc_cpp-Line3029.icc
# Step 2
iccFromXml ub-load-of-value-not-valid-IccMpeCalc_cpp-Line3029.icc oops.icc
```

---

## iccFromXml

### #651 — HBO: HBO in icCurvesFromXml() at IccTagXml.cpp:3330

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/651) · Fix: [PR#658](https://github.com/InternationalColorConsortium/iccDEV/pull/658)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/xml/icc/hbo-icCurvesFromXml-IccTagXml_cpp-Line333.xml
# Step 2
ASAN_OPTIONS=print_scariness=1:halt_on_error=0 iccFromXml hbo-icCurvesFromXml-IccTagXml_cpp-Line333.xml foo.bar
```

### #633 — NPD: NPD in CIccTagXmlStruct::ParseTag() at IccTagXml.cpp:4738

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/633) · Fix: [PR#639](https://github.com/InternationalColorConsortium/iccDEV/pull/639)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/xml/icc/segv-CIccTagXmlStruct-ParseTag-IccTagXml_cpp-Line4738.xml
# Step 2
iccFromXml segv-CIccTagXmlStruct-ParseTag-IccTagXml_cpp-Line4738.xml foo.bar
```

### #614 — HBO: HBO in CIccTagTextDescription::Release() at IccTagBasic.cpp:2350

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/614)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/xml/icc/hbo-CIccTagTextDescription-Release-IccTagBasic_cpp-Line2350.xml
# Step 2
iccFromXml hbo-CIccTagTextDescription-Release-IccTagBasic_cpp-Line2350.xml foo.bar
```

### #609 — HBO: HBO in CIccTagTextDescription::Release() at IccTagBasic.cpp:2350

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/609) · Fix: [PR#610](https://github.com/InternationalColorConsortium/iccDEV/pull/610)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/xml/icc/hbo-CIccTagTextDescription-Release-IccTagBasic_cpp-Line2350.xml
# Step 2
iccFromXml hbo-CIccTagTextDescription-Release-IccTagBasic_cpp-Line2350.xml foo.bar
```

### #559 — HBO: HBO in CIccIO::WriteUInt16Float() at IccIO.cpp:298

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/559) · Fix: [PR#561](https://github.com/InternationalColorConsortium/iccDEV/pull/561)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/heap-buffer-overflow-CIccIO-WriteUInt16Float-IccIO_cpp-Line298.xml
# Step 2
iccFromXml heap-buffer-overflow-CIccIO-WriteUInt16Float-IccIO_cpp-Line298.xml foo.bar
```

### #539 — TC: Type Confusion in CIccTagEmbeddedHeightImage::Validate() at IccProfLib/IccTagBasic.cpp:12084

CWE-843 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/539) · Fix: [PR#547](https://github.com/InternationalColorConsortium/iccDEV/pull/547)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/ub-runtime-error-type-confusion-IccTagBasic_cpp-Line12084.xml
# Step 2
iccFromXml ub-runtime-error-type-confusion-IccTagBasic_cpp-Line12084.xml foo.icc
```

### #533 — UB: UB runtime error in  at IccUtilXml.cpp:1057

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/533)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/ub-nan16-outside-range-IccUtilXml_cpp-Line1057.xml
# Step 2
iccFromXml ub-nan-outside-range-unsigned-int-IccUtilXml_cpp-Line1044.xml foo.icc
```

### #532 — UB: UB runtime error in  at IccLibXML/IccUtilXml.cpp:1044

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/532) · Fix: [PR#541](https://github.com/InternationalColorConsortium/iccDEV/pull/541)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/ub-nan-outside-range-unsigned-int-IccUtilXml_cpp-Line1044.xml
# Step 2
iccFromXml ub-nan-outside-range-unsigned-int-IccUtilXml_cpp-Line1044.xml foo.icc
```

### #529 — UB: UB runtime error in icVectorApplyMatrix3x3() at IccProfLib/IccUtil.cpp:560

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/529) · Fix: [PR#543](https://github.com/InternationalColorConsortium/iccDEV/pull/543)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/ub-nan-outside-range-IccUtil_cpp-Line560.xml
# Step 2
iccFromXml ub-nan-outside-range-IccUtil_cpp-Line560.xml out.icc
```

### #518 — HBO: heap-buffer-overflow in icCurvesFromXml() at IccXML/IccLibXML/IccTagXml.cpp:3294

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/518) · Fix: [PR#521](https://github.com/InternationalColorConsortium/iccDEV/pull/521)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/xml/icc/heap-buffer-overflow-icCurvesFromXml-IccTagXml_cpp-Line3294.xml
# Step 2
iccFromXml heap-buffer-overflow-icCurvesFromXml-IccTagXml_cpp-Line3294.xml heap-buffer-overflow-icCurvesFromXml-IccTagXml_cpp-Line3294.icc
```

### #507 — NPD: NPD & UB in CIccProfileXml::ParseBasic() at IccXML/IccLibXML/IccProfileXml.cpp:493

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/507) · Fix: [PR#515](https://github.com/InternationalColorConsortium/iccDEV/pull/515)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/fuzz/refs/heads/master/xml/icc/npd-ub-runtime-error-null-pointer-IccProfileXml_cpp-L493.xml
# Step 2
iccFromXml npd-ub-runtime-error-null-pointer-IccProfileXml_cpp-L493.xml Line493.icc
```

### #485 — NPD: NPD in CIccProfileXml::ParseTag() at IccLibXML/IccProfileXml.cpp:751

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/485)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/Commodity-Injection-Signatures/refs/heads/master/xml/icc/ub-member-access-null-pointer-struct-xmlnode.xml
# Step 2
iccFromXml ub-member-access-null-pointer-struct-xmlnode.xml oops.icc
```

### #484 — NPD: NPD & UB runtime error: member access .. null pointer at IccLibXML/IccTagXml.cpp:1578

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/484) · Fix: [PR#513](https://github.com/InternationalColorConsortium/iccDEV/pull/513)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/Commodity-Injection-Signatures/refs/heads/master/xml/icc/ub-member-access-null-pointer-struct-xmlnode.xml
# Step 2
iccFromXml ub-member-access-null-pointer-struct-xmlnode.xml oops.icc
```

### #480 — HBO: heap-buffer-overflow in CIccTagNamedColor2::SetSize() at IccProfLib/IccTagBasic.cpp:2850

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/480) · Fix: [PR#511](https://github.com/InternationalColorConsortium/iccDEV/pull/511)

```bash
# Step 1
wget https://raw.githubusercontent.com/xsscx/Commodity-Injection-Signatures/refs/heads/master/xml/icc/heap-buffer-overflow-CIccTagNamedColor2-CIccTagNamedColor2-IccProfLib-IccTagBasic_cpp-Line2850.xml
# Step 2
iccFromXml  heap-buffer-overflow-CIccTagNamedColor2-CIccTagNamedColor2-IccProfLib-IccTagBasic_cpp-Line2850.xml oops.icc
```

---

## iccRoundTrip

### #620 — HBO: HBO in CIccCLUT::Interp3d() at IccTagLut.cpp:2721

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/620)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/npd-CIccMpeCalculator-GetNewApply-IccMpeCalc_cpp-Line4929.icc
# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 npd-CIccMpeCalculator-GetNewApply-IccMpeCalc_cpp-Line4929.icc 0
```

### #617 — HBO: HBO in CIccCalculatorFunc::InitSelectOp() at IccMpeCalc.cpp:3663

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/617) · Fix: [PR#622](https://github.com/InternationalColorConsortium/iccDEV/pull/622)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc
# Step 2
iccRoundTrip hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc
```

### #552 — OOB: OOB in CIccXform3DLut::Apply() at IccCmm.cpp:5793

CWE-125 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/552) · Fix: [PR#563](https://github.com/InternationalColorConsortium/iccDEV/pull/563)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/ub-runtime-error-index16-oob-IccCmm_cpp-Line5793.icc
# Step 2
iccRoundTrip ub-runtime-error-index16-oob-IccCmm_cpp-Line5793.icc
```

### #550 — SEGV: SEGV in CIccMpeCurveSet::SetSize() at IccMpeBasic.cpp:3128

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/550) · Fix: [PR#566](https://github.com/InternationalColorConsortium/iccDEV/pull/566)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/segv-null-pointer-deref-CIccMpeCurveSet-SetSize-IccMpeBasic.cpp-Line3128.icc
# Step 2
iccRoundTrip segv-null-pointer-deref-CIccMpeCurveSet-SetSize-IccMpeBasic.cpp-Line3128.icc
```

### #526 — UB: UB runtime error in GetColumnsForRow() at IccProfLib/IccSparseMatrix.h:178

CWE-843 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/526) · Fix: [PR#542](https://github.com/InternationalColorConsortium/iccDEV/pull/542)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/sigsegv-address-not-mapped-CIccSparseMatrix-GetColumnsForRow-IccSparseMatrix_h-Line178.icc
# Step 2
iccRoundTrip sigsegv-address-not-mapped-CIccSparseMatrix-GetColumnsForRow-IccSparseMatrix_h-Line178.icc
```

### #483 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:3633

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/483)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-load-of-value-not-valid-icSigCalcOp.icc
# Step 2
iccRoundTrip ub-load-of-value-not-valid-icSigCalcOp.icc
```

### #482 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:3967

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/482)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-load-of-value-not-valid-icSigCalcOp.icc
# Step 2
iccRoundTrip ub-load-of-value-not-valid-icSigCalcOp.icc
```

### #481 — UB: UB runtime error: load of value .. not a valid value at IccProfLib/IccMpeCalc.cpp:3928

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/481) · Fix: [PR#512](https://github.com/InternationalColorConsortium/iccDEV/pull/512)

```bash
# Step 1
wget https://github.com/xsscx/Commodity-Injection-Signatures/raw/refs/heads/master/graphics/icc/ub-load-of-value-not-valid-icSigCalcOp.icc
# Step 2
iccRoundTrip ub-load-of-value-not-valid-icSigCalcOp.icc
```

---

## iccApplyProfiles

### #656 — HBO: HBO in CTiffImg::ReadLine() at TiffImg.cpp:370

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/656) · Fix: [PR#659](https://github.com/InternationalColorConsortium/iccDEV/pull/659)

```bash
# Step 1
wget https://github.com/xsscx/research/raw/refs/heads/main/test-profiles/Rec2020rgbSpectral.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hbo-CTiffImg-ReadLine-TiffImg_cpp-Line370.tiff
# Step 2
ASAN_OPTIONS=print_scariness=1 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles hbo-CTiffImg-ReadLine-TiffImg_cpp-Line370.tiff foo.tif 0 0 0 0 1 Rec2020rgbSpectral.icc 1
```

### #649 — SBO: SBO in CIccXform3DLut::Apply() at IccCmm.cpp:5873

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/649)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/sbo-CIccXform3DLut-Apply-IccCmm_cpp-Line5873.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/test_rgb.tif
# Step 3
ASAN_OPTIONS=print_scariness=1:detect_leaks=0 iccApplyProfiles test_rgb.tif foo.tif 0 0 0 0 1 sbo-CIccXform3DLut-Apply-IccCmm_cpp-Line5873.icc 40
```

### #646 — UB: UB nan outside range at iccApplyProfiles.cpp:560

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/646) · Fix: [PR#654](https://github.com/InternationalColorConsortium/iccDEV/pull/654)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/ub-nan-outside-range-iccApplyProfiles_cpp-Line560.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/test_rgb.tif
# Step 3
ASAN_OPTIONS=detect_leaks=0 iccApplyProfiles test_rgb.tif ub-out.tif 1 0 0 0 0 ub-nan-outside-range-iccApplyProfiles_cpp-Line560.icc 0
```

### #645 — SEGV: SEGV in CIccCLUT::Interp3d() at IccTagLut.cpp:2741

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/645) · Fix: [PR#653](https://github.com/InternationalColorConsortium/iccDEV/pull/653)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/segv-CIccCLUT-Interp3d-IccTagLut_cpp-Line2741.icc
# Step 2
ASAN_OPTIONS=detect_leaks=0:print_scariness=1 iccApplyProfiles foo.tif /tmp/out.tif 0 0 0 0 0 segv-CIccCLUT-Interp3d-IccTagLut_cpp-Line2741.icc 0
```

### #644 — SEGV: SEGV in CIccCalculatorFunc::ApplySequence() at IccMpeCalc.cpp:3711

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/644) · Fix: [PR#652](https://github.com/InternationalColorConsortium/iccDEV/pull/652)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc
# Step 2
echo SUkqAAgAAAAIAAABAwABAAAAAgAAAAEBAwABAAAAAgAAAAIBAwADAAAAbgAAAAMBAwABAAAAAQAAAAYBAwABAAAAAgAAABEBBAABAAAAdAAAABUBAwABAAAAAwAAABcBBAABAAAADAAAAAAAAAAIAAgACAD/AAAA/wAAAP+AgIA= | base64 -d > foo.tif
# Step 3
ASAN_OPTIONS=detect_leaks=0:print_scariness=1 iccApplyProfiles foo.tif bar.tif 0 0 0 0 0 segv-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3711.icc 1
```

### #613 — TC: TC in CIccCmm::AddXform() at IccCmm.cpp:8320

CWE-843 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/613)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/test_8x8.tif
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/huaf-CIccCmm-AddXform-IccCmm_cpp-Line8320.icc
# Step 3
iccApplyProfiles test_8x8.tif /tmp/out.tif 2 1 0 0 0 huaf-CIccCmm-AddXform-IccCmm_cpp-Line8320.icc 0
```

### #612 — HUAF: HUAF in CIccCmm::AddXform() at IccCmm.cpp:8320

CWE-416 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/612) · Fix: [PR#616](https://github.com/InternationalColorConsortium/iccDEV/pull/616)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/test_8x8.tif
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/huaf-CIccCmm-AddXform-IccCmm_cpp-Line8320.icc
# Step 3
iccApplyProfiles test_8x8.tif /tmp/out.tif 2 1 0 0 0 huaf-CIccCmm-AddXform-IccCmm_cpp-Line8320.icc 0
```

### #577 — MEMCPY: memcpy-param-overlap in CIccTagMultiProcessElement::Apply()

CWE-119 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/577) · Fix: [PR#579](https://github.com/InternationalColorConsortium/iccDEV/pull/579)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.tiff
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc
# Step 3
iccApplyProfiles memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.tiff  /tmp/out.tif 0 0 0 0 0 memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc 0
```

### #531 — TC: TC in CIccTagArray::Cleanup() at IccTagComposite.cpp:1514

CWE-843 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/531) · Fix: [PR#567](https://github.com/InternationalColorConsortium/iccDEV/pull/567)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hoyt-heap-use-after-free-ub-type-confusion.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
# Step 3
iccApplyProfiles hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff /tmp/out.tiff 0 0 0 0 0 hoyt-heap-use-after-free-ub-type-confusion.icc 0
```

### #530 — HUAF: Heap Use-After-Free in CIccTagArray::Cleanup() at IccProfLib/IccTagComposite.cpp:1514

CWE-416 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/530)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hoyt-heap-use-after-free-ub-type-confusion.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
# Step 3
iccApplyProfiles hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff /tmp/out.tiff 0 0 0 0 0 hoyt-heap-use-after-free-ub-type-confusion.icc 0
```

---

## iccApplyNamedCmm

### #625 — SBO: SBO in CIccPcsXform::pushXYZConvert() at IccCmm.cpp:3000

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/625) · Fix: [PR#632](https://github.com/InternationalColorConsortium/iccDEV/pull/632)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc
# Step 3
printf "'RGB '\nicEncodeFloat\n0.5\t0.5\t0.5\n" | iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm /dev/stdin 3 1 hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc 1 hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc 1
```

### #623 — HBO: HBO in CIccCalculatorFunc::ApplySequence() at IccMpeCalc.cpp:3711

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/623) · Fix: [PR#635](https://github.com/InternationalColorConsortium/iccDEV/pull/635)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc
# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | Tools/IccApplyNamedCmm/iccApplyNamedCmm /dev/stdin 3 0 hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc 0
```

### #621 — HBO: HBO in CIccMatrixMath::SetRange() at IccMatrixMath.cpp:379

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/621) · Fix: [PR#636](https://github.com/InternationalColorConsortium/iccDEV/pull/636)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccMatrixMath-SetRange-IccMatrixMath_cpp-Line379.icc
# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 hbo-CIccMatrixMath-SetRange-IccMatrixMath_cpp-Line379.icc 0
```

### #619 — HBO: HBO in CIccTagFloatNum<(icTagTypeSignature)>::Interpolate() at IccTagBasic.cpp:6789

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/619)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccOpDefSubElement-Exec-IccMpeCalc_cpp-Line377.icc
# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 hbo-CIccOpDefSubElement-Exec-IccMpeCalc_cpp-Line377.icc 0
```

### #618 — SBO: SBO in CIccTagNum<(icTagTypeSignature)>::GetValues() at IccTagBasic.cpp:6098

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/618) · Fix: [PR#638](https://github.com/InternationalColorConsortium/iccDEV/pull/638)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc
# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0  sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc 0
```

### #551 — SBO: SBO in CIccTagFloatNum::GetValues() at IccTagBasic.cpp:6634

CWE-121 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/551) · Fix: [PR#565](https://github.com/InternationalColorConsortium/iccDEV/pull/565)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc
# Step 2
iccApplyNamedCmm Tools/CmdLine/IccApplyNamedCmm/DataSetFiles/DarkRed-RGB.txt 3 0 stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc 0
```

---

## iccFromCube

### #607 — SIO: SIO in `bool parse3DTable()` at iccFromCube.cpp#L218

CWE-190 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/607) · Fix: [PR#611](https://github.com/InternationalColorConsortium/iccDEV/pull/611)

```bash
# Step 1
iccFromCube input.icc output.icc
```

---

## iccTiffDump

### #544 — SEGV: SEGV in DumpProfileInfo() at iccTiffDump.cpp:128

CWE-476 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/544)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
# Step 2
iccTiffDump hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff exported.icc
```

### #538 — UB: UB runtime error in CIccTagSparseMatrixArray::Read() at IccTagBasic.cpp:4684

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/538) · Fix: [PR#546](https://github.com/InternationalColorConsortium/iccDEV/pull/546)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/ub-enum-icSparseMatrixType-IccTagBasic_cpp-L4690.tiff
# Step 2
iccTiffDump  ub-enum-icSparseMatrixType-IccTagBasic_cpp-L4690.tiff
```

### #528 — UB: UB runtime error in DumpProfileInfo() at iccTiffDump.cpp:125

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/528)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
# Step 2
iccTiffDump hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
```

### #527 — UB: UB runtime error in DumpProfileInfo() at iccTiffDump.cpp:171

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/527) · Fix: [PR#549](https://github.com/InternationalColorConsortium/iccDEV/pull/549)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/tif/hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
# Step 2
iccTiffDump hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff
```

---

## iccV5DspObsToV4Dsp

### #650 — UB: Fix: UB in CIccProfileSharedPtr pccIcc()

CWE-758 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/650) · Fix: [PR#657](https://github.com/InternationalColorConsortium/iccDEV/pull/657)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/ub-runtime-error-icFloatNumber-IccMpeBasic_cpp-Line1825.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/crash_obs.icc
# Step 3
ASAN_OPTIONS=detect_leaks=0 iccV5DspObsToV4Dsp  ub-runtime-error-icFloatNumber-IccMpeBasic_cpp-Line1825.icc crash_obs.icc foo.icc
```

### #576 — OOM: OOM in CIccTagDict::Read() of 120 GB

CWE-400 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/576) · Fix: [PR#578](https://github.com/InternationalColorConsortium/iccDEV/pull/578)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc
# Step 2
iccV5DspObsToV4Dsp oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc Testing/sRGB_v4_ICC_preference.icc /tmp/120G.icc
```

### #558 — HBO: HBO in CIccFileIO::Read8() at IccIO.cpp:508

CWE-122 · [Issue](https://github.com/InternationalColorConsortium/iccDEV/issues/558) · Fix: [PR#562](https://github.com/InternationalColorConsortium/iccDEV/pull/562)

```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc
# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/heap-buffer-overflow-observer-CIccFileIO-Read8-IccIO_cpp-Line508.icc
# Step 3
iccV5DspObsToV4Dsp heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc heap-buffer-overflow-observer-CIccFileIO-Read8-IccIO_cpp-Line508.icc foo.bar
```

---

## Environment Setup

All reproductions require iccDEV built with ASAN+UBSAN:

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
cmake Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
make -j$(nproc)

# Add tools to PATH
export PATH="$PWD/Tools/IccDumpProfile:$PWD/Tools/IccToXml:$PWD/Tools/IccFromXml:$PATH"
export PATH="$PWD/Tools/IccRoundTrip:$PWD/Tools/IccApplyProfiles:$PATH"
export PATH="$PWD/Tools/IccApplyNamedCmm:$PWD/Tools/IccFromCube:$PATH"
export PATH="$PWD/Tools/IccTiffDump:$PWD/Tools/IccV5DspObsToV4Dsp:$PATH"
export LD_LIBRARY_PATH="$PWD/IccProfLib:$PWD/IccXML:$LD_LIBRARY_PATH"

# Common ASAN options for reproduction
export ASAN_OPTIONS=halt_on_error=0:detect_leaks=0:print_scariness=1
```

## Cross-Reference: Issue → PR

| Issue | Bug Type | Tool | Fix PR |
|-------|----------|------|--------|
| [#656](https://github.com/InternationalColorConsortium/iccDEV/issues/656) | HBO | `iccApplyProfiles` | [#659](https://github.com/InternationalColorConsortium/iccDEV/pull/659) |
| [#651](https://github.com/InternationalColorConsortium/iccDEV/issues/651) | HBO | `iccFromXml` | [#658](https://github.com/InternationalColorConsortium/iccDEV/pull/658) |
| [#650](https://github.com/InternationalColorConsortium/iccDEV/issues/650) | UB | `iccV5DspObsToV4Dsp` | [#657](https://github.com/InternationalColorConsortium/iccDEV/pull/657) |
| [#649](https://github.com/InternationalColorConsortium/iccDEV/issues/649) | SBO | `iccApplyProfiles` | — |
| [#646](https://github.com/InternationalColorConsortium/iccDEV/issues/646) | UB | `iccApplyProfiles` | [#654](https://github.com/InternationalColorConsortium/iccDEV/pull/654) |
| [#645](https://github.com/InternationalColorConsortium/iccDEV/issues/645) | SEGV | `iccApplyProfiles` | [#653](https://github.com/InternationalColorConsortium/iccDEV/pull/653) |
| [#644](https://github.com/InternationalColorConsortium/iccDEV/issues/644) | SEGV | `iccApplyProfiles` | [#652](https://github.com/InternationalColorConsortium/iccDEV/pull/652) |
| [#633](https://github.com/InternationalColorConsortium/iccDEV/issues/633) | NPD | `iccFromXml` | [#639](https://github.com/InternationalColorConsortium/iccDEV/pull/639) |
| [#629](https://github.com/InternationalColorConsortium/iccDEV/issues/629) | SO | `iccDumpProfile` | [#630](https://github.com/InternationalColorConsortium/iccDEV/pull/630) |
| [#628](https://github.com/InternationalColorConsortium/iccDEV/issues/628) | SO | `iccToXml` | — |
| [#627](https://github.com/InternationalColorConsortium/iccDEV/issues/627) | HBO | `iccToXml` | [#631](https://github.com/InternationalColorConsortium/iccDEV/pull/631) |
| [#625](https://github.com/InternationalColorConsortium/iccDEV/issues/625) | SBO | `iccApplyNamedCmm` | [#632](https://github.com/InternationalColorConsortium/iccDEV/pull/632) |
| [#624](https://github.com/InternationalColorConsortium/iccDEV/issues/624) | SBO | `iccToXml` | [#634](https://github.com/InternationalColorConsortium/iccDEV/pull/634) |
| [#623](https://github.com/InternationalColorConsortium/iccDEV/issues/623) | HBO | `iccApplyNamedCmm` | [#635](https://github.com/InternationalColorConsortium/iccDEV/pull/635) |
| [#621](https://github.com/InternationalColorConsortium/iccDEV/issues/621) | HBO | `iccApplyNamedCmm` | [#636](https://github.com/InternationalColorConsortium/iccDEV/pull/636) |
| [#620](https://github.com/InternationalColorConsortium/iccDEV/issues/620) | HBO | `iccRoundTrip` | — |
| [#619](https://github.com/InternationalColorConsortium/iccDEV/issues/619) | HBO | `iccApplyNamedCmm` | — |
| [#618](https://github.com/InternationalColorConsortium/iccDEV/issues/618) | SBO | `iccApplyNamedCmm` | [#638](https://github.com/InternationalColorConsortium/iccDEV/pull/638) |
| [#617](https://github.com/InternationalColorConsortium/iccDEV/issues/617) | HBO | `iccRoundTrip` | [#622](https://github.com/InternationalColorConsortium/iccDEV/pull/622) |
| [#614](https://github.com/InternationalColorConsortium/iccDEV/issues/614) | HBO | `iccFromXml` | — |
| [#613](https://github.com/InternationalColorConsortium/iccDEV/issues/613) | TC | `iccApplyProfiles` | — |
| [#612](https://github.com/InternationalColorConsortium/iccDEV/issues/612) | HUAF | `iccApplyProfiles` | [#616](https://github.com/InternationalColorConsortium/iccDEV/pull/616) |
| [#609](https://github.com/InternationalColorConsortium/iccDEV/issues/609) | HBO | `iccFromXml` | [#610](https://github.com/InternationalColorConsortium/iccDEV/pull/610) |
| [#607](https://github.com/InternationalColorConsortium/iccDEV/issues/607) | SIO | `iccFromCube` | [#611](https://github.com/InternationalColorConsortium/iccDEV/pull/611) |
| [#599](https://github.com/InternationalColorConsortium/iccDEV/issues/599) | SIO | `iccToXml` | — |
| [#577](https://github.com/InternationalColorConsortium/iccDEV/issues/577) | MEMCPY | `iccApplyProfiles` | [#579](https://github.com/InternationalColorConsortium/iccDEV/pull/579) |
| [#576](https://github.com/InternationalColorConsortium/iccDEV/issues/576) | OOM | `iccV5DspObsToV4Dsp` | [#578](https://github.com/InternationalColorConsortium/iccDEV/pull/578) |
| [#568](https://github.com/InternationalColorConsortium/iccDEV/issues/568) | OOM | `iccDumpProfile` | [#572](https://github.com/InternationalColorConsortium/iccDEV/pull/572) |
| [#560](https://github.com/InternationalColorConsortium/iccDEV/issues/560) | NPD | `iccDumpProfile` | — |
| [#559](https://github.com/InternationalColorConsortium/iccDEV/issues/559) | HBO | `iccFromXml` | [#561](https://github.com/InternationalColorConsortium/iccDEV/pull/561) |
| [#558](https://github.com/InternationalColorConsortium/iccDEV/issues/558) | HBO | `iccV5DspObsToV4Dsp` | [#562](https://github.com/InternationalColorConsortium/iccDEV/pull/562) |
| [#553](https://github.com/InternationalColorConsortium/iccDEV/issues/553) | NPD | `iccDumpProfile` | — |
| [#552](https://github.com/InternationalColorConsortium/iccDEV/issues/552) | OOB | `iccRoundTrip` | [#563](https://github.com/InternationalColorConsortium/iccDEV/pull/563) |
| [#551](https://github.com/InternationalColorConsortium/iccDEV/issues/551) | SBO | `iccApplyNamedCmm` | [#565](https://github.com/InternationalColorConsortium/iccDEV/pull/565) |
| [#550](https://github.com/InternationalColorConsortium/iccDEV/issues/550) | SEGV | `iccRoundTrip` | [#566](https://github.com/InternationalColorConsortium/iccDEV/pull/566) |
| [#544](https://github.com/InternationalColorConsortium/iccDEV/issues/544) | SEGV | `iccTiffDump` | — |
| [#539](https://github.com/InternationalColorConsortium/iccDEV/issues/539) | TC | `iccFromXml` | [#547](https://github.com/InternationalColorConsortium/iccDEV/pull/547) |
| [#538](https://github.com/InternationalColorConsortium/iccDEV/issues/538) | UB | `iccTiffDump` | [#546](https://github.com/InternationalColorConsortium/iccDEV/pull/546) |
| [#537](https://github.com/InternationalColorConsortium/iccDEV/issues/537) | SBO | `iccToXml` | [#545](https://github.com/InternationalColorConsortium/iccDEV/pull/545) |
| [#533](https://github.com/InternationalColorConsortium/iccDEV/issues/533) | UB | `iccFromXml` | — |
| [#532](https://github.com/InternationalColorConsortium/iccDEV/issues/532) | UB | `iccFromXml` | [#541](https://github.com/InternationalColorConsortium/iccDEV/pull/541) |
| [#531](https://github.com/InternationalColorConsortium/iccDEV/issues/531) | TC | `iccApplyProfiles` | [#567](https://github.com/InternationalColorConsortium/iccDEV/pull/567) |
| [#530](https://github.com/InternationalColorConsortium/iccDEV/issues/530) | HUAF | `iccApplyProfiles` | — |
| [#529](https://github.com/InternationalColorConsortium/iccDEV/issues/529) | UB | `iccFromXml` | [#543](https://github.com/InternationalColorConsortium/iccDEV/pull/543) |
| [#528](https://github.com/InternationalColorConsortium/iccDEV/issues/528) | UB | `iccTiffDump` | — |
| [#527](https://github.com/InternationalColorConsortium/iccDEV/issues/527) | UB | `iccTiffDump` | [#549](https://github.com/InternationalColorConsortium/iccDEV/pull/549) |
| [#526](https://github.com/InternationalColorConsortium/iccDEV/issues/526) | UB | `iccRoundTrip` | [#542](https://github.com/InternationalColorConsortium/iccDEV/pull/542) |
| [#518](https://github.com/InternationalColorConsortium/iccDEV/issues/518) | HBO | `iccFromXml` | [#521](https://github.com/InternationalColorConsortium/iccDEV/pull/521) |
| [#507](https://github.com/InternationalColorConsortium/iccDEV/issues/507) | NPD | `iccFromXml` | [#515](https://github.com/InternationalColorConsortium/iccDEV/pull/515) |
| [#499](https://github.com/InternationalColorConsortium/iccDEV/issues/499) | UB | `iccToXml` | [#516](https://github.com/InternationalColorConsortium/iccDEV/pull/516) |
| [#492](https://github.com/InternationalColorConsortium/iccDEV/issues/492) | UB | `iccToXml` | — |
| [#491](https://github.com/InternationalColorConsortium/iccDEV/issues/491) | UB | `iccToXml` | — |
| [#490](https://github.com/InternationalColorConsortium/iccDEV/issues/490) | UB | `iccDumpProfile` | — |
| [#489](https://github.com/InternationalColorConsortium/iccDEV/issues/489) | UB | `iccDumpProfile` | — |
| [#488](https://github.com/InternationalColorConsortium/iccDEV/issues/488) | UB | `iccDumpProfile` | — |
| [#487](https://github.com/InternationalColorConsortium/iccDEV/issues/487) | UB | `iccDumpProfile` | — |
| [#486](https://github.com/InternationalColorConsortium/iccDEV/issues/486) | UB | `iccDumpProfile` | — |
| [#485](https://github.com/InternationalColorConsortium/iccDEV/issues/485) | NPD | `iccFromXml` | — |
| [#484](https://github.com/InternationalColorConsortium/iccDEV/issues/484) | NPD | `iccFromXml` | [#513](https://github.com/InternationalColorConsortium/iccDEV/pull/513) |
| [#483](https://github.com/InternationalColorConsortium/iccDEV/issues/483) | UB | `iccRoundTrip` | — |
| [#482](https://github.com/InternationalColorConsortium/iccDEV/issues/482) | UB | `iccRoundTrip` | — |
| [#481](https://github.com/InternationalColorConsortium/iccDEV/issues/481) | UB | `iccRoundTrip` | [#512](https://github.com/InternationalColorConsortium/iccDEV/pull/512) |
| [#480](https://github.com/InternationalColorConsortium/iccDEV/issues/480) | HBO | `iccFromXml` | [#511](https://github.com/InternationalColorConsortium/iccDEV/pull/511) |
