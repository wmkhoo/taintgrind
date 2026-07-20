#!/usr/bin/env python3
"""Backward-slice taintgrind JSONL traces to the dependency cone of goals."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable


def operand_key(obj: dict) -> tuple[str, int, int] | None:
    kind = obj.get("kind")
    if kind not in {"tmp", "reg"}:
        return None
    def_seq = int(obj.get("def_seq") or 0)
    if def_seq <= 0:
        return None
    return kind, int(obj.get("id") or 0), def_seq


def dst_key(event: dict) -> tuple[str, int, int] | None:
    dst = event.get("dst")
    return operand_key(dst) if isinstance(dst, dict) else None


def operands_in(obj) -> Iterable[dict]:
    if isinstance(obj, dict):
        if obj.get("kind") in {"tmp", "reg"}:
            yield obj
        for value in obj.values():
            yield from operands_in(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from operands_in(item)


def event_deps(event: dict) -> set[tuple[str, int, int]]:
    deps: set[tuple[str, int, int]] = set()
    for key in ("args", "guard", "address", "data", "iftrue", "iffalse", "index"):
        if key in event:
            for obj in operands_in(event[key]):
                dep = operand_key(obj)
                if dep is not None:
                    deps.add(dep)
    return deps


def source_addrs_for_event(event: dict) -> set[int]:
    addrs: set[int] = set()
    if event.get("op") != "Load":
        return addrs
    address = int(event.get("address", {}).get("value", "0x0"), 16)
    bits = int(event.get("bits") or 8)
    for offset in range((bits + 7) // 8):
        addrs.add(address + offset)
    return addrs


def slice_events(events: list[dict], target_seqs: set[int] | None = None) -> list[dict]:
    stmt_by_seq = {
        int(event["seq"]): event
        for event in events
        if event.get("event") == "stmt" and "seq" in event
    }
    def_by_key = {
        key: event
        for event in stmt_by_seq.values()
        if (key := dst_key(event)) is not None
    }
    if target_seqs is None:
        target_seqs = {
            int(event["seq"])
            for event in stmt_by_seq.values()
            if event.get("op") == "Exit" and int(str(event.get("taint", "0x0")), 16)
        }

    needed_seqs = set(target_seqs)
    needed_keys: set[tuple[str, int, int]] = set()
    needed_source_addrs: set[int] = set()
    work = [stmt_by_seq[seq] for seq in target_seqs if seq in stmt_by_seq]

    while work:
        event = work.pop()
        needed_source_addrs.update(source_addrs_for_event(event))
        for dep in event_deps(event):
            if dep in needed_keys:
                continue
            needed_keys.add(dep)
            def_event = def_by_key.get(dep)
            if def_event is None:
                continue
            seq = int(def_event["seq"])
            if seq not in needed_seqs:
                needed_seqs.add(seq)
                work.append(def_event)

    sliced = []
    for event in events:
        if event.get("event") == "meta":
            sliced.append(event)
        elif event.get("event") == "source":
            addr = int(event["addr"], 16)
            if addr in needed_source_addrs:
                sliced.append(event)
        elif event.get("event") == "stmt" and int(event.get("seq") or -1) in needed_seqs:
            sliced.append(event)
    return sliced


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--seq", type=int, action="append", help="target sequence to retain; defaults to tainted exits")
    args = parser.parse_args()

    events = load_events(args.trace)
    sliced = slice_events(events, set(args.seq) if args.seq else None)
    with args.output.open("w", encoding="utf-8") as f:
        for event in sliced:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
    print(f"sliced {len(events)} -> {len(sliced)} events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
