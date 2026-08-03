# Fuzzer Map

This map separates library-level CFL harnesses from AFL++ CLI lanes. AFL lanes
use real tool argv shapes from `afl/targets.sh`; injection lanes fuzz embedded
ICC profile bytes through fixed media, while dump lanes fuzz the media file
itself.

```mermaid
graph LR
    subgraph CFL["CFL LibFuzzer harnesses"]
    fuzzer_icc_applynamedcmm_fuzzer["applynamedcmm"]:::fuzzer
    comp_iccdev_tools_IccApplyNamedCmm(["IccApplyNamedCmm"]):::tool
    fuzzer_icc_applynamedcmm_fuzzer -->|75%| comp_iccdev_tools_IccApplyNamedCmm
    fuzzer_icc_applyprofiles_fuzzer["applyprofiles"]:::fuzzer
    comp_iccdev_tools_IccApplyProfiles(["IccApplyProfiles"]):::tool
    fuzzer_icc_applyprofiles_fuzzer --> comp_iccdev_tools_IccApplyProfiles
    fuzzer_icc_applysearch_fuzzer["applysearch"]:::fuzzer
    comp_iccdev_tools_IccApplySearch(["IccApplySearch"]):::tool
    fuzzer_icc_applysearch_fuzzer --> comp_iccdev_tools_IccApplySearch
    fuzzer_icc_cfg_fuzzer["cfg"]:::fuzzer
    comp_iccdev_tools_IccApplyNamedCmm(["IccApplyNamedCmm"]):::tool
    fuzzer_icc_cfg_fuzzer --> comp_iccdev_tools_IccApplyNamedCmm
    fuzzer_icc_dump_fuzzer["dump"]:::fuzzer
    comp_iccdev_tools_IccDumpProfile(["IccDumpProfile"]):::tool
    fuzzer_icc_dump_fuzzer -->|100%| comp_iccdev_tools_IccDumpProfile
    fuzzer_icc_fromcube_fuzzer["fromcube"]:::fuzzer
    comp_iccdev_tools_IccFromCube(["IccFromCube"]):::tool
    fuzzer_icc_fromcube_fuzzer -->|100%| comp_iccdev_tools_IccFromCube
    fuzzer_icc_fromxml_fuzzer["fromxml"]:::fuzzer
    fuzzer_icc_link_fuzzer["link"]:::fuzzer
    comp_iccdev_tools_IccApplyToLink(["IccApplyToLink"]):::tool
    fuzzer_icc_link_fuzzer -->|65%| comp_iccdev_tools_IccApplyToLink
    fuzzer_icc_roundtrip_fuzzer["roundtrip"]:::fuzzer
    comp_iccdev_tools_IccRoundTrip(["IccRoundTrip"]):::tool
    fuzzer_icc_roundtrip_fuzzer -->|95%| comp_iccdev_tools_IccRoundTrip
    fuzzer_icc_specsep_fuzzer["specsep"]:::fuzzer
    comp_iccdev_tools_IccSpecSepToTiff(["IccSpecSepToTiff"]):::tool
    fuzzer_icc_specsep_fuzzer -->|85%| comp_iccdev_tools_IccSpecSepToTiff
    fuzzer_icc_tiffdump_fuzzer["tiffdump"]:::fuzzer
    comp_iccdev_tools_IccTiffDump(["IccTiffDump"]):::tool
    fuzzer_icc_tiffdump_fuzzer --> comp_iccdev_tools_IccTiffDump
    fuzzer_icc_toxml_fuzzer["toxml"]:::fuzzer
    fuzzer_icc_v5dspobs_fuzzer["v5dspobs"]:::fuzzer
    comp_iccdev_tools_IccV5DspObsToV4Dsp(["IccV5DspObsToV4Dsp"]):::tool
    fuzzer_icc_v5dspobs_fuzzer --> comp_iccdev_tools_IccV5DspObsToV4Dsp
    end

    subgraph AFL["AFL++ CLI lanes"]
    afl_jpegdump["jpegdump: JPEG media seeds"]:::afl
    afl_jpegdump_inject["jpegdump-inject: ICC profile injection"]:::afl
    afl_pngdump["pngdump: PNG media seeds"]:::afl
    afl_pngdump_inject["pngdump-inject: ICC profile injection"]:::afl
    afl_tiffdump["tiffdump: TIFF media seeds"]:::afl
    afl_tiffdump_extract["tiffdump-extract: TIFF saved ICC extraction"]:::afl
    afl_report["report.sh: status, map, triage, coverage"]:::report
    afl_coverage["coverage.sh: cov-analysis and reachability"]:::report
    afl_reset["clean baseline: clear generated reports, tmp, profile counters"]:::report
    afl_qa["QA rerun: fresh queues and reports"]:::report
    end

    comp_iccdev_tools_IccJpegDump(["IccJpegDump"]):::tool
    comp_iccdev_tools_IccPngDump(["IccPngDump"]):::tool
    comp_iccdev_tools_IccTiffDump(["IccTiffDump"]):::tool

    afl_jpegdump --> comp_iccdev_tools_IccJpegDump
    afl_jpegdump_inject --> comp_iccdev_tools_IccJpegDump
    afl_pngdump --> comp_iccdev_tools_IccPngDump
    afl_pngdump_inject --> comp_iccdev_tools_IccPngDump
    afl_tiffdump --> comp_iccdev_tools_IccTiffDump
    afl_tiffdump_extract --> comp_iccdev_tools_IccTiffDump
    afl_report --> afl_coverage
    afl_coverage --> afl_reset
    afl_reset --> afl_qa

    classDef fuzzer fill:#1565c0,color:#fff,stroke:#0d47a1
    classDef afl fill:#6a1b9a,color:#fff,stroke:#4a148c
    classDef tool fill:#2e7d32,color:#fff,stroke:#1b5e20
    classDef report fill:#455a64,color:#fff,stroke:#263238
```
