#!/usr/bin/env python3
"""Extract taintgrind source-byte assignments from Z3 model output."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SOURCE_RE = re.compile(
    r"\(define-fun\s+(src_[A-Za-z0-9_.-]+_(\d+)_([0-9a-fA-F]+))\s+\(\)\s+\(_\s+BitVec\s+8\)\s+#x([0-9a-fA-F]{2})\s*\)",
    re.MULTILINE,
)


def split_models(text: str) -> list[str]:
    models: list[str] = []
    pos = 0
    while True:
        sat_at = text.find("sat", pos)
        if sat_at < 0:
            break
        next_sat = text.find("\nsat", sat_at + 3)
        chunk = text[sat_at: next_sat if next_sat >= 0 else len(text)]
        if "(define-fun" in chunk:
            models.append(chunk)
        pos = next_sat + 1 if next_sat >= 0 else len(text)
    return models


def extract_model(model: str) -> list[tuple[int, int, str, str]]:
    rows = []
    for match in SOURCE_RE.finditer(model):
        symbol, index, addr, value = match.groups()
        rows.append((int(index), int(value, 16), addr.lower(), symbol))
    rows.sort(key=lambda row: row[0])
    return rows


def render(models: list[list[tuple[int, int, str, str]]]) -> str:
    lines: list[str] = []
    for model_no, rows in enumerate(models, 1):
        if not rows:
            continue
        data = bytearray(max(index for index, _, _, _ in rows) + 1)
        for index, value, _, _ in rows:
            data[index] = value
        lines.append(f"model {model_no}:")
        lines.append(f"  hex: {data.hex()}")
        lines.append(f"  c-escaped: {''.join(f'\\\\x{b:02x}' for b in data)}")
        for index, value, addr, symbol in rows:
            lines.append(f"  [{index}] 0x{value:02x} addr=0x{addr} symbol={symbol}")
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path, help="Z3 output containing one or more models")
    args = parser.parse_args()

    text = args.model.read_text(encoding="utf-8")
    models = [extract_model(chunk) for chunk in split_models(text)]
    output = render(models)
    if not output:
        print("no source-byte assignments found", file=sys.stderr)
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
