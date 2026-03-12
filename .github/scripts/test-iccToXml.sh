#!/bin/bash
# test-iccToXml.sh — iccToXml envelope tests
# Usage: ./test-iccToXml.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

TOXML="$TOOLS/IccToXml/iccToXml"
echo "=== iccToXml ==="

run_test "toxml-01" "Convert sRGB to XML" "$TOXML" "$SRGB" "$OUTDIR/sRGB.xml"
run_test "toxml-02" "Convert CMYK to XML" "$TOXML" "$CMYK" "$OUTDIR/CMYK.xml"
run_test "toxml-03" "Convert NamedColor to XML" "$TOXML" "$NAMED" "$OUTDIR/NamedColor.xml"
run_test "toxml-04" "Convert v5 Rec2020 spectral to XML" "$TOXML" "$REC2020" "$OUTDIR/Rec2020.xml"
run_test "toxml-05" "Convert 17-channel to XML" "$TOXML" "$MULTICHAN" "$OUTDIR/17Chan.xml"
run_test "toxml-06" "Convert DisplayP3 to XML" "$TOXML" "$DISPLAY_P3" "$OUTDIR/DisplayP3.xml"
run_test "toxml-07" "Convert v5 LCDDisplay to XML" "$TOXML" "$V5_DISPLAY" "$OUTDIR/LCDDisplay.xml"

# PoC profiles through XML serialization
POC_XML_COUNT=0
for poc in "$TP"/hbo-*.icc "$TP"/sbo-*.icc "$TP"/segv-*.icc "$TP"/ub-*.icc "$TP"/cve-*.icc; do
  if [ -f "$poc" ] && [ "$POC_XML_COUNT" -lt 10 ]; then
    base=$(basename "$poc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "toxml-poc-$base" "PoC→XML: $(basename "$poc" | cut -c1-45)" \
      "$TOXML" "$poc" "$OUTDIR/poc_${base}.xml"
    POC_XML_COUNT=$((POC_XML_COUNT + 1))
  fi
done

print_summary "iccToXml"
exit $FAIL
