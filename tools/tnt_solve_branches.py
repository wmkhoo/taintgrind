#!/usr/bin/env python3
"""Solve each taintgrind Exit branch flip independently with Z3."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import tnt_model_to_input
import tnt_trace_to_smt


def exit_seqs(events: list[dict]) -> list[int]:
    return [
        int(event["seq"])
        for event in events
        if event.get("event") == "stmt" and event.get("op") == "Exit" and "guard" in event
    ]


def solve_one(z3: str, smt: str) -> tuple[str, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False, encoding="utf-8") as f:
        f.write(smt)
        smt_path = Path(f.name)
    try:
        proc = subprocess.run(
            [z3, str(smt_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return proc.stdout, proc.stderr
    finally:
        smt_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="taintgrind JSONL trace")
    parser.add_argument("--z3", default="z3", help="Z3 executable [z3]")
    parser.add_argument("--limit", type=int, help="maximum number of Exit branches to solve")
    parser.add_argument("--only-sat", action="store_true", help="only print satisfiable branches")
    parser.add_argument("--input-alphabet", help="restrict source bytes to these ASCII characters")
    args = parser.parse_args()

    events = tnt_trace_to_smt.load_events(args.trace)
    seqs = exit_seqs(events)
    if args.limit is not None:
        seqs = seqs[: args.limit]

    sat_count = 0
    unsat_count = 0
    unknown_count = 0

    for seq in seqs:
        smt = tnt_trace_to_smt.convert(
            events,
            branch_seq=seq,
            input_alphabet=args.input_alphabet.encode("ascii") if args.input_alphabet else None,
        )
        stdout, stderr = solve_one(args.z3, smt)
        result = stdout.splitlines()[0] if stdout.splitlines() else "unknown"

        if result == "sat":
            sat_count += 1
            models = [tnt_model_to_input.extract_model(chunk) for chunk in tnt_model_to_input.split_models(stdout)]
            rendered = tnt_model_to_input.render(models).rstrip()
            print(f"branch seq {seq}: sat")
            if rendered:
                print(rendered)
        elif result == "unsat":
            unsat_count += 1
            if not args.only_sat:
                print(f"branch seq {seq}: unsat")
        else:
            unknown_count += 1
            if not args.only_sat:
                print(f"branch seq {seq}: {result}")
                if stderr:
                    print(stderr.rstrip(), file=sys.stderr)

    print(f"summary: sat={sat_count} unsat={unsat_count} unknown={unknown_count} total={len(seqs)}")
    return 0 if unknown_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
