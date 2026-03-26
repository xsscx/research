# Patch Impact

```mermaid
graph TD
    OOS{"OOS"}
    CFL_031["CFL-031: tool-only"]
    OOS --> CFL_031
    CFL_032["CFL-032: tool-only"]
    OOS --> CFL_032
    CFL_033["CFL-033: tool-only"]
    OOS --> CFL_033
    CFL_035["CFL-035: tool-only"]
    OOS --> CFL_035
    CFL_036["CFL-036: tool-only"]
    OOS --> CFL_036
    CFL_038["CFL-038: tool-only"]
    OOS --> CFL_038
    CFL_040["CFL-040: tool-only"]
    OOS --> CFL_040
    CFL_041["CFL-041: tool-only"]
    OOS --> CFL_041
    P0{"P0"}
    CFL_001["CFL-001: xml-runtime"]
    P0 --> CFL_001
    CFL_002["CFL-002: profile-runtime"]
    P0 --> CFL_002
    CFL_004["CFL-004: profile-runtime"]
    P0 --> CFL_004
    CFL_007["CFL-007: profile-runtime"]
    P0 --> CFL_007
    CFL_019["CFL-019: profile-runtime"]
    P0 --> CFL_019
    CFL_021["CFL-021: profile-runtime"]
    P0 --> CFL_021
    CFL_022["CFL-022: cmm-runtime"]
    P0 --> CFL_022
    CFL_025["CFL-025: cmm-runtime"]
    P0 --> CFL_025
    P1{"P1"}
    CFL_005["CFL-005: profile-runtime"]
    P1 --> CFL_005
    CFL_006["CFL-006: profile-runtime"]
    P1 --> CFL_006
    CFL_008["CFL-008: cmm-runtime"]
    P1 --> CFL_008
    CFL_014["CFL-014: cmm-runtime"]
    P1 --> CFL_014
    CFL_023["CFL-023: cmm-runtime"]
    P1 --> CFL_023
    CFL_046["CFL-046: cmm-runtime"]
    P1 --> CFL_046
    CFL_051["CFL-051: profile-runtime"]
    P1 --> CFL_051
    CFL_056["CFL-056: profile-runtime"]
    P1 --> CFL_056
    P2{"P2"}
    CFL_009["CFL-009: profile-runtime"]
    P2 --> CFL_009
    CFL_017["CFL-017: xml-runtime"]
    P2 --> CFL_017
    CFL_028["CFL-028: profile-runtime"]
    P2 --> CFL_028
    CFL_029["CFL-029: profile-runtime"]
    P2 --> CFL_029
    CFL_044["CFL-044: cmm-runtime"]
    P2 --> CFL_044
    CFL_045["CFL-045: cmm-runtime"]
    P2 --> CFL_045
    CFL_047["CFL-047: cmm-runtime"]
    P2 --> CFL_047
    CFL_048["CFL-048: profile-runtime"]
    P2 --> CFL_048
    P3{"P3"}
    CFL_053["CFL-053: profile-runtime"]
    P3 --> CFL_053
    CFL_054["CFL-054: profile-runtime"]
    P3 --> CFL_054
    CFL_068["CFL-068: profile-runtime"]
    P3 --> CFL_068
    CFL_069["CFL-069: profile-runtime"]
    P3 --> CFL_069
    CFL_070["CFL-070: profile-runtime"]
    P3 --> CFL_070
    CFL_071["CFL-071: profile-runtime"]
    P3 --> CFL_071
    CFL_072["CFL-072: profile-runtime"]
    P3 --> CFL_072
    CFL_073["CFL-073: xml-runtime"]
    P3 --> CFL_073

    classDef covered fill:#4caf50,color:#fff
    classDef uncovered fill:#f44336,color:#fff
```
