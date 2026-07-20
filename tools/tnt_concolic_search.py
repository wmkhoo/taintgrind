#!/usr/bin/env python3
"""Simple stdin-based concolic search using taintgrind traces and Z3.

Exploration policy:

* Execute the target concretely under taintgrind with one stdin candidate.
* Convert the emitted trace into one flipped-branch SMT query per tainted Exit.
* Consider branches from the end of the trace toward the start, so candidates
  tend to preserve a longer already-executed path prefix.
* Merge model bytes only through the deepest source byte loaded before the
  flipped branch. This keeps unexplored suffix bytes from being overwritten by
  arbitrary model choices.
* Queue candidates by target progress, then flipped branch sequence, then input
  depth. Targets can expose progress with exit codes, as the maze harness does
  by returning larger codes for deeper wall collisions.
"""

from __future__ import annotations

import argparse
import json
import heapq
import os
import subprocess
import tempfile
from pathlib import Path

import tnt_model_to_input
import tnt_solve_branches
import tnt_slice_trace
import tnt_trace_to_smt


#VALGRIND = Path(__file__).resolve().parents[2] / "build/bin/valgrind"
VALGRIND = Path(__file__).resolve().parents[2] / "./vg-in-place"
Z3 = "z3"
BRANCH_LIMIT = 10
AUTO_GOAL_LIMIT = 1
GOAL_WINDOW_SIZE = 3


def candidate_priority(exit_code: int, branch_seq: int, max_input_index: int) -> int:
    return -(exit_code * 1000000 + branch_seq * 1000 + max_input_index)


def run_trace(
    valgrind: Path,
    target: Path,
    target_args: list[str],
    data: bytes,
    workdir: Path,
    full_trace: bool = False,
) -> tuple[int, Path]:
    valgrind = valgrind.resolve()
    target = target.resolve()
    inp = tempfile.NamedTemporaryFile(delete=False, dir=workdir)
    inp.write(data)
    inp.close()
    trace = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl", dir=workdir)
    trace.close()
    with open(inp.name, "rb") as stdin:
        cmd = [
            str(valgrind),
            "--tool=taintgrind",
            "--taint-stdin=yes",
            "--smt2=yes",
            f"--trace-file={trace.name}",
        ]
        if full_trace:
            cmd.append("--tainted-ins-only=no")
        proc = subprocess.run(
            [
                *cmd,
                str(target),
                *target_args,
            ],
            stdin=stdin,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    Path(inp.name).unlink(missing_ok=True)
    return proc.returncode, Path(trace.name)


def source_index_by_addr(events: list[dict]) -> dict[int, int]:
    return {
        int(event["addr"], 16): int(event["index"])
        for event in events
        if event.get("event") == "source"
    }


def max_input_index_before(events: list[dict], seq: int, addr_to_index: dict[int, int]) -> int:
    max_index = -1
    for event in events:
        if event.get("event") != "stmt" or int(event.get("seq") or 0) > seq:
            continue
        if event.get("op") != "Load":
            continue
        address = int(event.get("address", {}).get("value", "0x0"), 16)
        bits = int(event.get("bits") or 8)
        for offset in range((bits + 7) // 8):
            index = addr_to_index.get(address + offset)
            if index is not None:
                max_index = max(max_index, index)
    return max_index


def tainted_exit_seqs(events: list[dict]) -> list[int]:
    return [
        int(event["seq"])
        for event in events
        if event.get("event") == "stmt"
        and event.get("op") == "Exit"
        and "guard" in event
        and int(str(event.get("taint", "0x0")), 16) != 0
    ]


def slice_for_search(events: list[dict], goals: list[tuple[int, int]] | None, branch_limit: int | None) -> list[dict]:
    target_seqs = set(goals_seq for goals_seq, _ in goals or [])
    branch_seqs = list(reversed(tainted_exit_seqs(events)))
    if branch_limit is not None:
        branch_seqs = branch_seqs[:branch_limit]
    target_seqs.update(branch_seqs)
    if not target_seqs:
        return tnt_slice_trace.slice_events(events, None)
    return tnt_slice_trace.slice_events(events, target_seqs)


def int_field(event: dict, key: str, default: int = 0) -> int:
    value = event.get(key)
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return int(str(value), 16)


def is_tainted(event: dict) -> bool:
    return int_field(event, "taint") != 0


def dst_bits(event: dict) -> int:
    dst = event.get("dst")
    if isinstance(dst, dict):
        return int(dst.get("bits") or 0)
    return int(event.get("bits") or 0)


def op_width(op: str, prefix: str) -> int | None:
    if not op.startswith(prefix):
        return None
    suffix = op.removeprefix(prefix)
    digits = ""
    for char in suffix:
        if not char.isdigit():
            break
        digits += char
    return int(digits) if digits else None


def all_ones(bits: int) -> int:
    return (1 << bits) - 1


def event_has_const_value(event: dict, value: int) -> bool:
    for arg in event.get("args") or []:
        if isinstance(arg, dict) and int_field(arg, "taint") == 0 and int_field(arg, "value") == value:
            return True
    return False


def inferred_goal_for_event(event: dict) -> tuple[int, int, int, str] | None:
    if event.get("event") != "stmt" or not is_tainted(event):
        return None
    op = str(event.get("op") or "")
    seq = int(event.get("seq") or 0)
    value = int_field(event, "value")

    if op in {"Sub32", "Sub64"} and value != 0:
        return 10, seq, 0, f"{op}=0"

    if op.startswith("CmpLE") and dst_bits(event) == 1 and value == 0:
        return 20, seq, 1, f"{op}=true"

    if op.startswith("CmpLT") and dst_bits(event) == 1 and value == 0:
        return 20, seq, 1, f"{op}=true"

    if op.startswith("CmpEQ") and dst_bits(event) == 1 and value == 0 and not event_has_const_value(event, 0x0a):
        return 30, seq, 1, f"{op}=true"

    if op.startswith("CmpNE") and dst_bits(event) == 1 and value != 0:
        return 30, seq, 0, f"{op}=false"

    if op == "GetMSBs8x16" and dst_bits(event) == 16 and value != 0xffff:
        return 50, seq, 0xffff, "GetMSBs8x16=all-ones"

    width = op_width(op, "CmpEQ8x")
    bits = dst_bits(event)
    if width is not None and bits == width * 8 and value != all_ones(bits):
        return 60, seq, all_ones(bits), f"{op}=all-ones"

    return None


def infer_goals(events: list[dict], limit: int = 1) -> list[tuple[int, int]]:
    inferred = [goal for event in events if (goal := inferred_goal_for_event(event)) is not None]
    inferred.sort(key=lambda item: (item[0], -item[1]))
    return [(seq, value) for _, seq, value, _ in inferred[:limit]]


def describe_inferred_goals(events: list[dict], goals: list[tuple[int, int]]) -> list[str]:
    description_by_goal = {}
    for event in events:
        inferred = inferred_goal_for_event(event)
        if inferred is None:
            continue
        _, seq, value, reason = inferred
        description_by_goal[(seq, value)] = f"{seq}=0x{value:x} ({reason})"
    return [description_by_goal[(seq, value)] for seq, value in goals if (seq, value) in description_by_goal]


def context_goals_before(events: list[dict], goals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not goals:
        return []
    goal_seqs = {seq for seq, _ in goals}
    last_goal_seq = max(goal_seqs)
    context = []
    for event in events:
        if event.get("event") != "stmt" or int(event.get("seq") or 0) >= last_goal_seq:
            continue
        if int(event.get("seq") or 0) in goal_seqs or dst_bits(event) != 1 or int_field(event, "value") == 0:
            continue
        op = str(event.get("op") or "")
        if is_tainted(event) and op.startswith("Cmp"):
            context.append((int(event["seq"]), 1))
    return context


def infer_zero_sub32_goals(events: list[dict], limit: int = 1) -> list[tuple[int, int]]:
    sub_goals = [
        goal
        for event in events
        if (goal := inferred_goal_for_event(event)) is not None and goal[3] in {"Sub32=0", "Sub64=0"}
    ]
    sub_goals.sort(key=lambda item: item[1], reverse=True)
    return [(seq, value) for _, seq, value, _ in sub_goals[:limit]]


def write_events(path: Path, events: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def solve_candidates(
    events: list[dict],
    current: bytes,
    alphabet: bytes | None,
    z3: str,
    branch_limit: int | None,
    goals: list[tuple[int, int]] | None = None,
    goal_window_size: int = 1,
) -> list[tuple[int, int, bytes]]:
    candidates: list[tuple[int, int, bytes]] = []
    addr_to_index = source_index_by_addr(events)
    if goals:
        goal_events = [
            event
            for event in events
            if not (event.get("event") == "stmt" and event.get("op") == "Exit")
        ]
        query_goals = [*context_goals_before(goal_events, goals), *goals]
        max_index = max(max_input_index_before(goal_events, seq, addr_to_index) for seq, _ in query_goals)
        if max_index < 0:
            max_index = max(addr_to_index.values(), default=-1)
        goal_seen: set[bytes] = set()
        max_window = max(1, goal_window_size)
        for window_size in range(1, max_window + 1):
            for start_index in range(max_index + 2 - window_size):
                open_indexes = set(range(start_index, start_index + window_size))
                fixed_inputs = {index: current[index] for index in range(max_index + 1) if index not in open_indexes and index < len(current)}
                smt = tnt_trace_to_smt.convert(goal_events, goals=query_goals, input_alphabet=alphabet, fixed_inputs=fixed_inputs)
                stdout, _ = tnt_solve_branches.solve_one(z3, smt)
                if not stdout.startswith("sat\n"):
                    continue
                for chunk in tnt_model_to_input.split_models(stdout):
                    rows = tnt_model_to_input.extract_model(chunk)
                    if not rows:
                        continue
                    data = bytearray(current)
                    for index, byte_value, _, _ in rows:
                        if index in open_indexes and index < len(data):
                            data[index] = byte_value
                    candidate = bytes(data)
                    if candidate not in goal_seen:
                        goal_seen.add(candidate)
                        candidates.append((max(seq for seq, _ in goals), max(open_indexes), candidate))
            if goal_seen:
                break
        if not goal_seen:
            smt = tnt_trace_to_smt.convert(goal_events, goals=query_goals, input_alphabet=alphabet)
            stdout, _ = tnt_solve_branches.solve_one(z3, smt)
            if stdout.startswith("sat\n"):
                for chunk in tnt_model_to_input.split_models(stdout):
                    rows = tnt_model_to_input.extract_model(chunk)
                    if not rows:
                        continue
                    data = bytearray(current)
                    for index, byte_value, _, _ in rows:
                        if index <= max_index and index < len(data):
                            data[index] = byte_value
                    candidate = bytes(data)
                    if candidate not in goal_seen:
                        goal_seen.add(candidate)
                        candidates.append((max(seq for seq, _ in goals), max_index, candidate))
    seqs = list(reversed(tnt_solve_branches.exit_seqs(events)))
    if branch_limit is not None:
        seqs = seqs[:branch_limit]
    for seq in seqs:
        max_index = max_input_index_before(events, seq, addr_to_index)
        smt = tnt_trace_to_smt.convert(events, branch_seq=seq, input_alphabet=alphabet)
        stdout, _ = tnt_solve_branches.solve_one(z3, smt)
        if not stdout.startswith("sat\n"):
            continue
        for chunk in tnt_model_to_input.split_models(stdout):
            rows = tnt_model_to_input.extract_model(chunk)
            if not rows:
                continue
            data = bytearray(current)
            for index, value, _, _ in rows:
                if index <= max_index and index < len(data):
                    data[index] = value
            candidates.append((seq, max_index, bytes(data)))
    return candidates


def search(args: argparse.Namespace, workdir: Path, keep_traces: bool) -> int:
    target_args = args.target_args
    if target_args and target_args[0] == "--":
        target_args = target_args[1:]
    alphabet = args.alphabet.encode("ascii") if args.alphabet else None
    counter = 0
    queue: list[tuple[int, int, bytes]] = [(0, counter, args.seed.encode("ascii"))]
    seen: set[bytes] = set()

    for run_no in range(1, args.max_runs + 1):
        if not queue:
            print(f"queue exhausted after {run_no - 1} runs")
            return 1
        _, _, data = heapq.heappop(queue)
        if data in seen:
            continue
        seen.add(data)

        code, trace = run_trace(VALGRIND, args.target, target_args, data, workdir, full_trace=True)
        print(f"run {run_no}: exit={code} input={data!r}", flush=True)
        if code == args.success_code:
            if keep_traces:
                trace.replace(workdir / f"trace_{run_no:04d}.raw.jsonl")
            else:
                trace.unlink(missing_ok=True)
            print(f"solution hex: {data.hex()}")
            print(f"solution ascii: {data!r}")
            return 0

        events = tnt_trace_to_smt.load_events(trace)
        goals = infer_goals(events, AUTO_GOAL_LIMIT)
        if goals:
            descriptions = describe_inferred_goals(events, goals)
            print(f"run {run_no}: inferred goals {descriptions or goals}", flush=True)

        before = len(events)
        events = slice_for_search(events, goals, BRANCH_LIMIT)
        print(f"run {run_no}: sliced trace {before} -> {len(events)} events", flush=True)
        if keep_traces:
            write_events(workdir / f"trace_{run_no:04d}.slice.jsonl", events)

        for seq, max_index, candidate in solve_candidates(
            events, data, alphabet, Z3, BRANCH_LIMIT, goals, GOAL_WINDOW_SIZE
        ):
            if candidate not in seen:
                counter += 1
                heapq.heappush(queue, (candidate_priority(code, seq, max_index), counter, candidate))
        if keep_traces:
            kept = workdir / f"trace_{run_no:04d}.raw.jsonl"
            trace.replace(kept)
        else:
            trace.unlink(missing_ok=True)

    print(f"no solution after {args.max_runs} runs; queued={len(queue)} seen={len(seen)}", flush=True)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", required=True, help="initial ASCII seed")
    parser.add_argument("--success-code", type=int, default=0, help="target exit code that means success [0]")
    parser.add_argument("--alphabet", help="restrict source bytes to these ASCII characters")
    parser.add_argument("--max-runs", type=int, default=100, help="maximum traced executions [100]")
    parser.add_argument("--trace-dir", type=Path, help="directory in which to retain raw and sliced traces")
    parser.add_argument("target", type=Path, help="target executable that reads stdin")
    parser.add_argument("target_args", nargs=argparse.REMAINDER, help="fixed target arguments after --")
    args = parser.parse_args()

    args.target = args.target.expanduser().resolve()
    if not args.target.exists():
        parser.error(f"target does not exist: {args.target}")
    if not args.target.is_file():
        parser.error(f"target is not a file: {args.target}")
    if not os.access(args.target, os.X_OK):
        parser.error(f"target is not executable: {args.target}")
    if not VALGRIND.is_file() or not os.access(VALGRIND, os.X_OK):
        parser.error(f"Valgrind launcher does not exist or is not executable: {VALGRIND}")

    if args.trace_dir:
        args.trace_dir.mkdir(parents=True, exist_ok=True)
        return search(args, args.trace_dir, keep_traces=True)
    with tempfile.TemporaryDirectory(prefix="tnt-concolic-") as tmp:
        return search(args, Path(tmp), keep_traces=False)


if __name__ == "__main__":
    raise SystemExit(main())
