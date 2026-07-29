#!/usr/bin/env python3
"""Directly adapt an iccDEV XML profile into iccDEV-style JSON.

This does not call iccFromXml and does not build an intermediate ICC profile.
It maps known XML tag and MPE element names to the JSON shape used by iccToJson,
while writing a sidecar findings file that preserves suspicious XML values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLS_DIR = REPO_ROOT / "iccDEV" / "Build" / "Tools"
NUMBER_RE = re.compile(r"[-+]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)")
UINT16_MAX = 0xFFFF
INT16_MIN = -0x8000
INT16_MAX = 0x7FFF

TAG_SIGNATURE_NAMES = {
    "desc": "profileDescriptionTag",
    "cprt": "copyrightTag",
    "wtpt": "mediaWhitePointTag",
    "bkpt": "mediaBlackPointTag",
    "chad": "chromaticAdaptationTag",
    "rXYZ": "redMatrixColumnTag",
    "gXYZ": "greenMatrixColumnTag",
    "bXYZ": "blueMatrixColumnTag",
    "rTRC": "redTRCTag",
    "gTRC": "greenTRCTag",
    "bTRC": "blueTRCTag",
    "A2B0": "AToB0Tag",
    "A2B1": "AToB1Tag",
    "A2B2": "AToB2Tag",
    "B2A0": "BToA0Tag",
    "B2A1": "BToA1Tag",
    "B2A2": "BToA2Tag",
    "D2B0": "DToB0Tag",
    "D2B1": "DToB1Tag",
    "D2B2": "DToB2Tag",
    "D2B3": "DToB3Tag",
    "B2D0": "BToD0Tag",
    "B2D1": "BToD1Tag",
    "B2D2": "BToD2Tag",
    "B2D3": "BToD3Tag",
    "svcn": "spectralViewingConditionsTag",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Directly convert ICC XML to iccDEV-style JSON without XML->ICC."
    )
    parser.add_argument("xml", help="ICC XML input profile")
    parser.add_argument(
        "-o",
        "--output",
        help="JSON output path (default: input filename with .direct.json suffix)",
    )
    parser.add_argument(
        "--findings",
        help="Findings sidecar path (default: output path with .findings.json suffix)",
    )
    parser.add_argument(
        "--test-json",
        action="store_true",
        help="Run iccFromJson on the generated JSON for sanitizer correlation",
    )
    parser.add_argument(
        "--tools-dir",
        default=os.environ.get("ICCDEV_TOOLS_DIR", str(DEFAULT_TOOLS_DIR)),
        help="iccDEV Build/Tools directory for --test-json",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for --test-json (default: 30)",
    )
    return parser.parse_args()


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def direct_text(elem: ElementTree.Element) -> str:
    return (elem.text or "").strip()


def child_text(elem: ElementTree.Element, name: str) -> str | None:
    child = elem.find(name)
    if child is None:
        return None
    text = direct_text(child)
    return text if text else None


def parse_number_token(value: str) -> int | float | None:
    value = value.strip()
    if not value:
        return None
    try:
        if value.lower().startswith(("0x", "+0x", "-0x")):
            sign = -1 if value.startswith("-") else 1
            return sign * int(value.lstrip("+-"), 16)
        if "." in value:
            return float(value)
        return int(value, 10)
    except ValueError:
        return None


def numeric_tokens(value: str) -> list[int | float]:
    numbers: list[int | float] = []
    for match in NUMBER_RE.finditer(value):
        parsed = parse_number_token(match.group(0))
        if parsed is not None:
            numbers.append(parsed)
    return numbers


def parse_number_list(value: str) -> list[int | float]:
    return numeric_tokens(value)


def parse_channel_count(
    elem: ElementTree.Element,
    attr: str,
    path: str,
    findings: list[dict[str, Any]],
) -> int:
    raw = elem.attrib.get(attr, "")
    values = numeric_tokens(raw)
    if not values:
        findings.append(
            {
                "path": path,
                "attribute": attr,
                "raw": raw,
                "issue": "missing or non-numeric channel count",
            }
        )
        return 0

    value = values[0]
    if not isinstance(value, int):
        findings.append(
            {
                "path": path,
                "attribute": attr,
                "raw": raw,
                "value": value,
                "issue": "channel count is not an integer",
            }
        )
        value = int(value)

    if len(values) > 1:
        findings.append(
            {
                "path": path,
                "attribute": attr,
                "raw": raw,
                "chosenValue": value,
                "extraValues": values[1:],
                "issue": "attribute contained multiple numeric tokens",
            }
        )

    record_integer_range(path, attr, raw, value, findings)
    return value


def record_integer_range(
    path: str,
    source: str,
    raw: str,
    value: int,
    findings: list[dict[str, Any]],
) -> None:
    if value < 0 or value > UINT16_MAX:
        findings.append(
            {
                "path": path,
                "source": source,
                "raw": raw,
                "value": value,
                "issue": "outside unsigned 16-bit range",
                "uint16Wrapped": value & UINT16_MAX,
            }
        )
    if value < INT16_MIN or value > INT16_MAX:
        findings.append(
            {
                "path": path,
                "source": source,
                "raw": raw,
                "value": value,
                "issue": "outside signed 16-bit range",
            }
        )


def convert_scalar(text: str) -> Any:
    values = numeric_tokens(text)
    if len(values) == 1 and NUMBER_RE.fullmatch(text.strip()):
        return values[0]
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return text


def convert_attrs(attrs: dict[str, str]) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    for key, value in attrs.items():
        converted[key] = convert_scalar(value)
    return converted


def convert_xyz(elem: ElementTree.Element) -> list[float]:
    return [
        float(elem.attrib.get("X", "0")),
        float(elem.attrib.get("Y", "0")),
        float(elem.attrib.get("Z", "0")),
    ]


def convert_header(header: ElementTree.Element | None) -> dict[str, Any]:
    if header is None:
        return {}

    out: dict[str, Any] = {}
    for child in list(header):
        name = strip_namespace(child.tag)
        if name == "PCSIlluminant":
            xyz = child.find("XYZNumber")
            if xyz is not None:
                out[name] = convert_xyz(xyz)
        elif name == "ProfileFlags":
            out["CMMFlags"] = convert_attrs(child.attrib)
        elif name == "DeviceAttributes":
            out[name] = convert_attrs(child.attrib)
        elif name == "SpectralRange":
            wavelengths = child.find("Wavelengths")
            if wavelengths is not None:
                out[name] = convert_attrs(wavelengths.attrib)
        else:
            text = direct_text(child)
            out[name] = convert_scalar(text) if text else convert_attrs(child.attrib)
    return out


def convert_tags(tags: ElementTree.Element | None, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if tags is None:
        return []

    converted: list[dict[str, Any]] = []
    for tag_elem in list(tags):
        xml_type = strip_namespace(tag_elem.tag)
        signature = child_text(tag_elem, "TagSignature") or xml_type
        json_tag_name = TAG_SIGNATURE_NAMES.get(signature, f"{signature}Tag")
        data = convert_tag_data(tag_elem, xml_type, f"IccProfile/Tags/{xml_type}", findings)
        converted.append({json_tag_name: {"data": data}})
    return converted


def convert_tag_data(
    tag_elem: ElementTree.Element,
    xml_type: str,
    path: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    if xml_type == "multiLocalizedUnicodeType":
        strings = []
        for text_elem in tag_elem.findall("LocalizedText"):
            language_country = text_elem.attrib.get("LanguageCountry", "")
            strings.append(
                {
                    "language": language_country[:2],
                    "country": language_country[2:4],
                    "text": direct_text(text_elem),
                }
            )
        return {"type": xml_type, "localizedStrings": strings}

    if xml_type == "multiProcessElementType":
        mpe = tag_elem.find("MultiProcessElements")
        if mpe is None:
            return {"type": xml_type, "inputChannels": 0, "outputChannels": 0, "elements": []}
        return {
            "type": xml_type,
            "inputChannels": parse_channel_count(mpe, "InputChannels", path, findings),
            "outputChannels": parse_channel_count(mpe, "OutputChannels", path, findings),
            "elements": [
                convert_mpe_element(child, f"{path}/MultiProcessElements", findings)
                for child in list(mpe)
                if strip_namespace(child.tag) != "TagSignature"
            ],
        }

    if xml_type == "XYZType":
        xyz = tag_elem.find("XYZNumber")
        return {"type": xml_type, "XYZ": convert_xyz(xyz) if xyz is not None else []}

    if xml_type == "spectralViewingConditionsType":
        return convert_spectral_viewing_conditions(tag_elem, xml_type)

    data: dict[str, Any] = {"type": xml_type}
    for child in list(tag_elem):
        name = strip_namespace(child.tag)
        if name == "TagSignature":
            continue
        data[name] = convert_generic_element(child)
    return data


def convert_mpe_element(
    elem: ElementTree.Element,
    parent_path: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    elem_type = strip_namespace(elem.tag)
    path = f"{parent_path}/{elem_type}"
    out: dict[str, Any] = {
        "type": elem_type,
        "inputChannels": parse_channel_count(elem, "InputChannels", path, findings),
        "outputChannels": parse_channel_count(elem, "OutputChannels", path, findings),
    }

    if elem_type == "CalculatorElement":
        sub_elements = elem.find("SubElements")
        if sub_elements is not None:
            out["subElements"] = [
                convert_named_sub_element(child, f"{path}/SubElements", findings)
                for child in list(sub_elements)
            ]
        main_function = child_text(elem, "MainFunction")
        if main_function is not None:
            out["mainFunction"] = main_function
        copy_optional_text(elem, out, "InputNames", "inputNames")
        copy_optional_text(elem, out, "OutputNames", "outputNames")
        return out

    if elem_type in ("MatrixElement", "EmissionMatrixElement", "InvEmissionMatrixElement"):
        matrix_text = child_text(elem, "MatrixData")
        if matrix_text:
            key = "matrixData" if elem_type != "MatrixElement" else "matrix"
            out[key] = parse_number_list(matrix_text)
        constants_text = child_text(elem, "Constants")
        if constants_text:
            out["constants"] = parse_number_list(constants_text)
        return out

    for child in list(elem):
        out[lower_first(strip_namespace(child.tag))] = convert_generic_element(child)
    return out


def convert_named_sub_element(
    elem: ElementTree.Element,
    parent_path: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    converted = convert_mpe_element(elem, parent_path, findings)
    converted.setdefault("name", f"element{len(parent_path)}")
    return converted


def convert_spectral_viewing_conditions(
    tag_elem: ElementTree.Element, xml_type: str
) -> dict[str, Any]:
    out: dict[str, Any] = {"type": xml_type}
    for child in list(tag_elem):
        name = strip_namespace(child.tag)
        if name == "TagSignature":
            continue
        if name in ("IlluminantXYZ", "SurroundXYZ"):
            out[name] = convert_xyz(child)
        elif name in ("ObserverFuncs", "IlluminantSPD"):
            item = convert_attrs(child.attrib)
            item["data"] = parse_number_list(direct_text(child))
            out[name] = item
        else:
            text = direct_text(child)
            out[name] = convert_scalar(text) if text else convert_attrs(child.attrib)
    return out


def convert_generic_element(elem: ElementTree.Element) -> Any:
    children = list(elem)
    text = direct_text(elem)
    if not children and not elem.attrib:
        return convert_scalar(text) if text else ""

    out: dict[str, Any] = {}
    if elem.attrib:
        out.update(convert_attrs(elem.attrib))
    if text:
        values = parse_number_list(text)
        out["data" if values else "text"] = values if values else text
    for child in children:
        out[strip_namespace(child.tag)] = convert_generic_element(child)
    return out


def copy_optional_text(
    elem: ElementTree.Element, out: dict[str, Any], xml_name: str, json_name: str
) -> None:
    value = child_text(elem, xml_name)
    if value is not None:
        out[json_name] = value


def lower_first(value: str) -> str:
    if not value:
        return value
    return value[0].lower() + value[1:]


def sanitizer_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = env.get(
        "ASAN_OPTIONS", "detect_leaks=0,halt_on_error=0,abort_on_error=0"
    )
    env["UBSAN_OPTIONS"] = env.get(
        "UBSAN_OPTIONS", "halt_on_error=0,print_stacktrace=1"
    )
    env["LLVM_PROFILE_FILE"] = env.get("LLVM_PROFILE_FILE", "/dev/null")
    lib_dirs = [
        REPO_ROOT / "iccDEV" / "Build" / "IccProfLib",
        REPO_ROOT / "iccDEV" / "Build" / "IccXML",
        REPO_ROOT / "iccDEV" / "Build" / "IccJSON",
        REPO_ROOT / "iccDEV" / "Build" / "IccMath",
    ]
    paths = [str(path) for path in lib_dirs if path.is_dir()]
    if env.get("LD_LIBRARY_PATH"):
        paths.append(env["LD_LIBRARY_PATH"])
    if paths:
        env["LD_LIBRARY_PATH"] = ":".join(paths)
    return env


def run_json_test(json_path: Path, tools_dir: Path, timeout: int) -> dict[str, Any]:
    tool = tools_dir / "IccFromJson" / "iccFromJson"
    if not tool.is_file():
        return {"skipped": True, "reason": f"missing tool: {tool}"}

    output_icc = json_path.with_suffix(".from-json.icc")
    log_path = json_path.with_suffix(".from-json.log")
    try:
        result = subprocess.run(
            [str(tool), str(json_path), str(output_icc)],
            cwd=REPO_ROOT,
            env=sanitizer_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        output = result.stdout + result.stderr
        log_path.write_text(output, encoding="utf-8")
        return {
            "skipped": False,
            "exitCode": result.returncode,
            "log": str(log_path),
            "outputIcc": str(output_icc) if output_icc.is_file() else None,
            "sanitizerLines": [
                line
                for line in output.splitlines()
                if "runtime error:" in line
                or "UndefinedBehaviorSanitizer" in line
                or "ERROR: AddressSanitizer" in line
            ],
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr
        log_path.write_text(output, encoding="utf-8")
        return {
            "skipped": False,
            "timedOut": True,
            "log": str(log_path),
            "sanitizerLines": [
                line
                for line in output.splitlines()
                if "runtime error:" in line
                or "UndefinedBehaviorSanitizer" in line
                or "ERROR: AddressSanitizer" in line
            ],
        }


def main() -> int:
    args = parse_args()
    xml_path = Path(args.xml).resolve()
    if not xml_path.is_file():
        print(f"XML input not found: {xml_path}", file=sys.stderr)
        return 64

    output_path = (
        Path(args.output).resolve()
        if args.output
        else xml_path.with_name(f"{xml_path.name}.direct.json")
    )
    findings_path = (
        Path(args.findings).resolve()
        if args.findings
        else output_path.with_suffix(".findings.json")
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.parent.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, Any]] = []
    root = ElementTree.parse(xml_path).getroot()
    if strip_namespace(root.tag) != "IccProfile":
        print(f"expected IccProfile root, got {root.tag}", file=sys.stderr)
        return 65

    profile = {
        "IccProfile": {
            "Header": convert_header(root.find("Header")),
            "Tags": convert_tags(root.find("Tags"), findings),
        }
    }
    output_path.write_text(json.dumps(profile, indent=2, sort_keys=False), encoding="utf-8")

    sidecar: dict[str, Any] = {
        "sourceXml": str(xml_path),
        "outputJson": str(output_path),
        "conversion": "direct XML-to-JSON; no iccFromXml and no intermediate ICC",
        "findings": findings,
    }
    if args.test_json:
        sidecar["iccFromJsonTest"] = run_json_test(
            output_path, Path(args.tools_dir).resolve(), args.timeout
        )
    findings_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8")

    print(f"json: {output_path}")
    print(f"findings: {findings_path}")
    print(f"findings_count: {len(findings)}")
    for finding in findings:
        if finding.get("uint16Wrapped") == 32520 or finding.get("value") == 360200:
            print(f"match: {finding}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
