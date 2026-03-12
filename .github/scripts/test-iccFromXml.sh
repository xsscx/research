#!/bin/bash
# test-iccFromXml.sh — iccFromXml envelope tests
# Usage: ./test-iccFromXml.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

FROMXML="$TOOLS/IccFromXml/iccFromXml"
TOXML="$TOOLS/IccToXml/iccToXml"
echo "=== iccFromXml ==="

# Pre-generate XML inputs (if not already present from iccToXml run)
for profile_name in sRGB CMYK NamedColor Rec2020; do
  case "$profile_name" in
    sRGB) src="$SRGB" ;;
    CMYK) src="$CMYK" ;;
    NamedColor) src="$NAMED" ;;
    Rec2020) src="$REC2020" ;;
  esac
  if [ -f "$src" ] && [ ! -f "$OUTDIR/${profile_name}.xml" ]; then
    "$TOXML" "$src" "$OUTDIR/${profile_name}.xml" > /dev/null 2>&1 || true
  fi
done

run_test "fromxml-01" "Reconstruct sRGB from XML" \
  "$FROMXML" "$OUTDIR/sRGB.xml" "$OUTDIR/sRGB_rt.icc"

run_test "fromxml-02" "Reconstruct CMYK from XML" \
  "$FROMXML" "$OUTDIR/CMYK.xml" "$OUTDIR/CMYK_rt.icc"

run_test "fromxml-03" "Reconstruct NamedColor from XML" \
  "$FROMXML" "$OUTDIR/NamedColor.xml" "$OUTDIR/NamedColor_rt.icc"

run_test "fromxml-04" "Reconstruct v5 Rec2020 from XML" \
  "$FROMXML" "$OUTDIR/Rec2020.xml" "$OUTDIR/Rec2020_rt.icc"

if [ -f "$HYBRID_XML" ]; then
  run_test "fromxml-05" "Parse upstream LCDDisplay XML" \
    "$FROMXML" "$HYBRID_XML" "$OUTDIR/LCDDisplay_from_xml.icc"
fi

run_test "fromxml-06" "FromXml with -noid flag" \
  "$FROMXML" "$OUTDIR/sRGB.xml" "$OUTDIR/sRGB_noid.icc" -noid

# Batch fuzz XML corpus
FUZZ_XML_COUNT=0
for xml_file in "$REPO_ROOT"/fuzz/xml/icc/*.xml; do
  if [ -f "$xml_file" ] && [ "$FUZZ_XML_COUNT" -lt 15 ]; then
    base=$(basename "$xml_file" .xml | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "fromxml-fuzz-$base" "Fuzz XML: $(basename "$xml_file" | cut -c1-45)" \
      "$FROMXML" "$xml_file" "$OUTDIR/fuzz_${base}.icc"
    FUZZ_XML_COUNT=$((FUZZ_XML_COUNT + 1))
  fi
done

# AFL-minimized XML corpus
FUZZ_MIN_COUNT=0
for xml_file in "$REPO_ROOT"/fuzz/xml/icc/minimized/*; do
  if [ -f "$xml_file" ] && [ "$FUZZ_MIN_COUNT" -lt 10 ]; then
    base=$(basename "$xml_file" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "fromxml-min-$base" "Minimized: $(basename "$xml_file" | cut -c1-45)" \
      "$FROMXML" "$xml_file" "$OUTDIR/min_${base}.icc"
    FUZZ_MIN_COUNT=$((FUZZ_MIN_COUNT + 1))
  fi
done

print_summary "iccFromXml"
exit $FAIL
