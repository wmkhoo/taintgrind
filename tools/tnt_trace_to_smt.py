#!/usr/bin/env python3
"""Convert taintgrind JSONL traces to SMT-LIBv2."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


BINOPS = {
    "Add": "bvadd",
    "Sub": "bvsub",
    "Mul": "bvmul",
    "And": "bvand",
    "Or": "bvor",
    "Xor": "bvxor",
    "Shl": "bvshl",
    "Shr": "bvlshr",
    "Sar": "bvashr",
}

CMPOPS = {
    "CmpEQ": "=",
    "CmpNE": "distinct",
    "CmpLT": {"S": "bvslt", "U": "bvult"},
    "CmpLE": {"S": "bvsle", "U": "bvule"},
}

IROP_CODE_NAMES = {
    5260: "16HLto32",
    5302: "CmpF64",
    6161: "AndV256",
    6164: "NotV256",
    6177: "CmpEQ8x32",
}


def bits_for_hex(value: str) -> int:
    return max(1, (len(value.removeprefix("0x")) or 1) * 4)


def bv(value: str | int, bits: int) -> str:
    if isinstance(value, str):
        n = int(value, 16) if value.startswith("0x") else int(value)
    else:
        n = value
    bits = max(1, bits)
    mask = (1 << bits) - 1
    width = (bits + 3) // 4
    return f"#x{n & mask:0{width}x}" if bits % 4 == 0 else f"(_ bv{n & mask} {bits})"


def name(obj: dict) -> str:
    kind = obj.get("kind")
    def_seq = int(obj.get("def_seq") or 0)
    ident = int(obj.get("id") or 0)
    ssa = int(obj.get("ssa") or 0)
    if kind == "tmp":
        return f"t{def_seq}_{ident}_{ssa}"
    if kind == "reg":
        return f"r{def_seq}_{ident}_{ssa}"
    raise ValueError(f"no SMT name for operand kind {kind!r}")


def operand(obj: dict, declared: dict[str, int], out: list[str]) -> tuple[str, int]:
    kind = obj.get("kind")
    bits = int(obj.get("bits") or 0) or bits_for_hex(obj.get("value", "0x0"))
    value = obj.get("value", "0x0")
    value_int = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
    if value_int >= (1 << bits):
        bits = bits_for_hex(value)
    taint = int(obj.get("taint", "0x0"), 16) if isinstance(obj.get("taint"), str) else int(obj.get("taint") or 0)
    if taint == 0:
        return bv(value, bits), bits
    if kind in {"tmp", "reg"} and int(obj.get("def_seq") or 0):
        sym = name(obj)
        declared_bits = declare(sym, bits, declared, out)
        return resize(sym, declared_bits, bits), bits
    return bv(obj.get("value", "0x0"), bits), bits


def declare(sym: str, bits: int, declared: dict[str, int], out: list[str]) -> int:
    if sym not in declared:
        out.append(f"(declare-fun {sym} () (_ BitVec {bits}))")
        declared[sym] = bits
    return declared[sym]


def resize(expr: str, from_bits: int, to_bits: int) -> str:
    if from_bits == to_bits:
        return expr
    if from_bits < to_bits:
        return f"((_ zero_extend {to_bits - from_bits}) {expr})"
    return f"((_ extract {to_bits - 1} 0) {expr})"


def operand_value(obj: dict) -> int:
    value = obj.get("value", "0x0")
    return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)


def parse_sized_op(op: str) -> tuple[str, int, str]:
    match = re.match(r"^([A-Za-z]+?)(\d+)([SU]?)$", op)
    if not match:
        return op, 0, ""
    return match.group(1), int(match.group(2)), match.group(3)


def is_cast_like_op(op: str) -> bool:
    return re.match(r"^(\d+)([US])?to\d+$", op) is not None or re.match(r"^\d+HIto\d+$", op) is not None


def ctz_expr(expr: str, bits: int, out_bits: int) -> str:
    result = bv(bits, out_bits)
    for index in range(bits - 1, -1, -1):
        bit = f"((_ extract {index} {index}) {expr})"
        result = f"(ite (= {bit} #b1) {bv(index, out_bits)} {result})"
    return result


def byte_lane(expr: str, index: int) -> str:
    return f"((_ extract {index * 8 + 7} {index * 8}) {expr})"


def cmp_eq_8x16(a: str, b: str) -> str:
    lanes = []
    for index in range(15, -1, -1):
        lanes.append(f"(ite (= {byte_lane(a, index)} {byte_lane(b, index)}) #xff #x00)")
    return f"(concat {' '.join(lanes)})"


def cmp_eq_8xn(a: str, b: str, lanes_count: int) -> str:
    lanes = []
    for index in range(lanes_count - 1, -1, -1):
        lanes.append(f"(ite (= {byte_lane(a, index)} {byte_lane(b, index)}) #xff #x00)")
    return f"(concat {' '.join(lanes)})"


def get_msbs_8x16(expr: str) -> str:
    bits = [f"((_ extract {index * 8 + 7} {index * 8 + 7}) {expr})" for index in range(15, -1, -1)]
    return f"(concat {' '.join(bits)})"


def mem_symbol(addr: int, version: int) -> str:
    return f"mem_{addr:x}_{version}"


def current_mem(addr: int, mem_versions: dict[int, int], declared: dict[str, int], out: list[str]) -> str:
    version = mem_versions.get(addr, 0)
    sym = mem_symbol(addr, version)
    declare(sym, 8, declared, out)
    return sym


def write_mem(addr: int, expr: str, mem_versions: dict[int, int], declared: dict[str, int], out: list[str]) -> str:
    version = mem_versions.get(addr, 0) + 1
    mem_versions[addr] = version
    sym = mem_symbol(addr, version)
    declare(sym, 8, declared, out)
    out.append(f"(assert (= {sym} {expr}))")
    return sym


def amd64_cc_width(cc_op: int) -> int | None:
    if cc_op in {1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49}:
        return 8
    if cc_op in {2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50}:
        return 16
    if cc_op in {3, 7, 11, 15, 19, 23, 27, 31, 35, 43, 47, 51, 53, 55, 57, 59, 61, 63}:
        return 32
    if cc_op in {4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 54, 56, 58, 60, 62, 64}:
        return 64
    return None


def amd64_cc_result(cc_op: int, args: list[dict], declared: dict[str, int], out: list[str]) -> tuple[str, int] | None:
    width = amd64_cc_width(cc_op)
    if width is None or len(args) < 4:
        return None
    dep1, dep1_bits = operand(args[2], declared, out)
    dep2, dep2_bits = operand(args[3], declared, out)
    if cc_op in {1, 2, 3, 4, 9, 10, 11, 12, 61, 62, 63, 64}:
        return f"(bvadd {resize(dep1, dep1_bits, width)} {resize(dep2, dep2_bits, width)})", width
    if cc_op in {5, 6, 7, 8, 13, 14, 15, 16}:
        return f"(bvsub {resize(dep1, dep1_bits, width)} {resize(dep2, dep2_bits, width)})", width
    if cc_op in {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 53, 54, 55, 56, 57, 58, 59, 60}:
        return resize(dep1, dep1_bits, width), width
    return None


def amd64_calculate_condition(event: dict, declared: dict[str, int], out: list[str]) -> tuple[str, int] | None:
    args = event.get("args") or []
    if len(args) < 5:
        return None
    cond = operand_value(args[0])
    cc_op = operand_value(args[1])
    result = amd64_cc_result(cc_op, args, declared, out)
    if result is None:
        return None
    expr, bits = result
    zero = bv(0, bits)
    if cond == 4:
        return f"(ite (= {expr} {zero}) {bv(1, 64)} {bv(0, 64)})", 64
    if cond == 5:
        return f"(ite (= {expr} {zero}) {bv(0, 64)} {bv(1, 64)})", 64
    return None


def amd64_calculate_rflags_all(event: dict, declared: dict[str, int], out: list[str]) -> tuple[str, int] | None:
    args = event.get("args") or []
    if len(args) < 4:
        return None
    cc_op = operand_value(args[0])
    pseudo_args = [{}, {"value": hex(cc_op)}, args[1], args[2]]
    result = amd64_cc_result(cc_op, pseudo_args, declared, out)
    if result is None:
        return None
    expr, bits = result
    zf = f"(ite (= {expr} {bv(0, bits)}) {bv(0x40, 64)} {bv(0, 64)})"
    return zf, 64


def op_expr(event: dict, declared: dict[str, int], out: list[str], mem_versions: dict[int, int]) -> tuple[str, int]:
    op = event.get("irop") or IROP_CODE_NAMES.get(event.get("irop_code")) or event.get("op", "")
    dst = event.get("dst") or {}
    dst_bits = int(dst.get("bits") or event.get("bits") or 0)
    args = event.get("args") or []

    if op in {"Load", "Get", "RdTmp", "Put"} and args:
        expr, bits = operand(args[0], declared, out)
        return resize(expr, bits, dst_bits or bits), dst_bits or bits

    if op == "Load":
        addr = int(event["address"]["value"], 16)
        bits = dst_bits or int(event.get("bits") or 8)
        parts = []
        concrete = event.get("bytes") or []
        for offset in range((bits + 7) // 8):
            if addr + offset in mem_versions:
                parts.append(current_mem(addr + offset, mem_versions, declared, out))
            elif offset < len(concrete):
                parts.append(bv(concrete[offset], 8))
            else:
                parts.append(current_mem(addr + offset, mem_versions, declared, out))
        expr = parts[0] if len(parts) == 1 else f"(concat {' '.join(reversed(parts))})"
        return expr, bits

    if op == "ITE" and args and "iftrue" in event and "iffalse" in event:
        c, cb = operand(args[0], declared, out)
        t, tb = operand(event["iftrue"], declared, out)
        f, fb = operand(event["iffalse"], declared, out)
        bits = dst_bits or max(tb, fb)
        cond = f"(not (= {resize(c, cb, 1)} #b0))"
        return f"(ite {cond} {resize(t, tb, bits)} {resize(f, fb, bits)})", bits

    if op == "16HLto32" and len(args) == 2:
        hi, hib = operand(args[0], declared, out)
        lo, lob = operand(args[1], declared, out)
        return f"(concat {resize(hi, hib, 16)} {resize(lo, lob, 16)})", 32

    if op == "32HLto64" and len(args) == 2:
        hi, hib = operand(args[0], declared, out)
        lo, lob = operand(args[1], declared, out)
        return f"(concat {resize(hi, hib, 32)} {resize(lo, lob, 32)})", 64

    if event.get("helper") == "amd64g_calculate_condition":
        modeled = amd64_calculate_condition(event, declared, out)
        if modeled is not None:
            return modeled

    if event.get("helper") == "amd64g_calculate_rflags_all":
        modeled = amd64_calculate_rflags_all(event, declared, out)
        if modeled is not None:
            return modeled

    base, bits, signedness = parse_sized_op(op)
    if base in BINOPS and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        bits = dst_bits or bits or max(ab, bb)
        return f"({BINOPS[base]} {resize(a, ab, bits)} {resize(b, bb, bits)})", bits

    if op in {"AndV128", "OrV128", "XorV128", "AndV256", "OrV256", "XorV256"} and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        bits = dst_bits or (256 if op.endswith("V256") else 128)
        smt_op = {"And": "bvand", "Or": "bvor", "Xor": "bvxor"}[op[:-4]]
        return f"({smt_op} {resize(a, ab, bits)} {resize(b, bb, bits)})", bits

    if base in {"CmpEQ", "CmpNE"} and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        bits = bits or max(ab, bb)
        pred = f"({CMPOPS[base]} {resize(a, ab, bits)} {resize(b, bb, bits)})"
        return f"(ite {pred} #b1 #b0)", 1

    if base in {"CmpLT", "CmpLE"} and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        bits = bits or max(ab, bb)
        cmpop = CMPOPS[base].get(signedness or "U", "bvult")
        return f"(ite ({cmpop} {resize(a, ab, bits)} {resize(b, bb, bits)}) #b1 #b0)", 1

    if op.startswith("Not") and len(args) == 1:
        a, ab = operand(args[0], declared, out)
        bits = dst_bits or bits or ab
        return f"(bvnot {resize(a, ab, bits)})", bits

    if op in {"CtzNat32", "CtzNat64"} and len(args) == 1:
        a, ab = operand(args[0], declared, out)
        in_bits = 32 if op == "CtzNat32" else 64
        out_bits = dst_bits or in_bits
        return ctz_expr(resize(a, ab, in_bits), in_bits, out_bits), out_bits

    if op == "CmpEQ8x16" and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        return cmp_eq_8xn(resize(a, ab, 128), resize(b, bb, 128), 16), 128

    if op == "CmpEQ8x32" and len(args) == 2:
        a, ab = operand(args[0], declared, out)
        b, bb = operand(args[1], declared, out)
        return cmp_eq_8xn(resize(a, ab, 256), resize(b, bb, 256), 32), 256

    if op == "GetMSBs8x16" and len(args) == 1:
        a, ab = operand(args[0], declared, out)
        return get_msbs_8x16(resize(a, ab, 128)), 16

    if len(args) == 1 and is_cast_like_op(op):
        a, ab = operand(args[0], declared, out)
        return resize(a, ab, dst_bits or ab), dst_bits or ab

    taint = int(event.get("taint", "0x0"), 16) if isinstance(event.get("taint"), str) else int(event.get("taint") or 0)
    if taint and dst:
        bits = dst_bits or bits_for_hex(event.get("value", "0x0"))
        return name(dst), bits

    return bv(event.get("value", "0x0"), dst_bits or bits_for_hex(event.get("value", "0x0"))), dst_bits or 64


def guard_predicate(guard: dict, declared: dict[str, int], out: list[str]) -> tuple[str, str]:
    expr, bits = operand(guard, declared, out)
    zero = bv(0, bits)
    observed = int(guard.get("value", "0x0"), 16) != 0
    taken = f"(not (= {expr} {zero}))"
    not_taken = f"(= {expr} {zero})"
    return (taken, not_taken) if observed else (not_taken, taken)


def convert(
    events: list[dict],
    check_sat: bool = False,
    get_model: bool = False,
    branch_queries: bool = False,
    branch_models: bool = False,
    branch_seq: int | None = None,
    goal_seq: int | None = None,
    goal_value: int | str | None = None,
    goals: list[tuple[int, int | str]] | None = None,
    input_alphabet: bytes | None = None,
    fixed_inputs: dict[int, int] | None = None,
) -> str:
    out = ["(set-logic QF_BV)"]
    declared: dict[str, int] = {}
    mem_versions: dict[int, int] = {}
    if goals is None:
        goals = []
    if fixed_inputs is None:
        fixed_inputs = {}
    if goal_seq is not None:
        if goal_value is None:
            raise ValueError("goal_value is required with goal_seq")
        goals = [*goals, (goal_seq, goal_value)]
    goal_map = {int(seq): value for seq, value in goals}
    seen_goals: set[int] = set()
    last_goal_seq = max(goal_map) if goal_map else None

    for event in events:
        if event.get("event") == "source":
            addr = int(event["addr"], 16)
            source = f"src_{event.get('name', 'byte')}_{event.get('index', 0)}_{addr:x}"
            mem_versions.setdefault(addr, 0)
            mem = current_mem(addr, mem_versions, declared, out)
            declare(source, 8, declared, out)
            if input_alphabet:
                choices = " ".join(f"(= {source} {bv(byte, 8)})" for byte in input_alphabet)
                out.append(f"(assert (or {choices}))")
            index = int(event.get("index", 0))
            if index in fixed_inputs:
                out.append(f"(assert (= {source} {bv(fixed_inputs[index], 8)}))")
            out.append(f"(assert (= {mem} {source}))")
            continue

        if event.get("event") != "stmt":
            continue

        op = event.get("op")
        if op == "Store":
            data, bits = operand(event["data"], declared, out)
            addr = int(event["address"]["value"], 16)
            for offset in range((bits + 7) // 8):
                if bits < 8:
                    byte = resize(data, bits, 8)
                else:
                    byte = f"((_ extract {offset * 8 + 7} {offset * 8}) {data})"
                write_mem(addr + offset, byte, mem_versions, declared, out)
            continue

        if op == "Exit" and "guard" in event:
            observed, flipped = guard_predicate(event["guard"], declared, out)
            is_target_branch = branch_seq is not None and int(event.get("seq") or -1) == branch_seq
            if branch_queries or is_target_branch:
                out.append(f"; branch seq {event.get('seq')} flipped")
                out.append("(push)")
                out.append(f"(assert {flipped})")
                out.append("(check-sat)")
                if branch_models or is_target_branch:
                    out.append("(get-model)")
                out.append("(pop)")
                if is_target_branch:
                    return "\n".join(out) + "\n"
            out.append(f"(assert {observed})")
            continue

        dst = event.get("dst")
        if not dst:
            continue
        sym = name(dst)
        bits = int(dst.get("bits") or 0) or bits_for_hex(event.get("value", "0x0"))
        declare(sym, bits, declared, out)
        expr, expr_bits = op_expr(event, declared, out, mem_versions)
        out.append(f"(assert (= {sym} {resize(expr, expr_bits, bits)}))")
        seq = int(event.get("seq") or -1)
        if seq in goal_map:
            seen_goals.add(seq)
            out.append(f"; goal seq {seq}")
            out.append(f"(assert (= {sym} {bv(goal_map[seq], bits)}))")
        if last_goal_seq is not None and seq >= last_goal_seq:
            missing = sorted(set(goal_map) - seen_goals)
            for missing_seq in missing:
                out.append(f"; goal seq {missing_seq} not found")
                out.append("(assert false)")
            out.append("(check-sat)")
            out.append("(get-model)")
            return "\n".join(out) + "\n"

    if goal_map:
        for missing_seq in sorted(set(goal_map) - seen_goals):
            out.append(f"; goal seq {missing_seq} not found")
            out.append("(assert false)")

    if check_sat or get_model:
        out.append("(check-sat)")
    if get_model:
        out.append("(get-model)")
    return "\n".join(out) + "\n"


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="taintgrind JSONL trace")
    parser.add_argument("-o", "--output", type=Path, help="SMT-LIBv2 output path")
    parser.add_argument("--check-sat", action="store_true", help="append (check-sat)")
    parser.add_argument("--get-model", action="store_true", help="append (check-sat) and (get-model)")
    parser.add_argument("--branch-queries", action="store_true", help="query the opposite direction for each Exit guard")
    parser.add_argument("--branch-models", action="store_true", help="emit (get-model) after each branch query")
    parser.add_argument("--branch-seq", type=int, help="query one Exit seq and stop after that query")
    parser.add_argument("--input-alphabet", help="restrict source bytes to these ASCII characters")
    args = parser.parse_args()

    smt = convert(
        load_events(args.trace),
        check_sat=args.check_sat,
        get_model=args.get_model,
        branch_queries=args.branch_queries,
        branch_models=args.branch_models,
        branch_seq=args.branch_seq,
        input_alphabet=args.input_alphabet.encode("ascii") if args.input_alphabet else None,
    )
    if args.output:
        args.output.write_text(smt, encoding="utf-8")
    else:
        sys.stdout.write(smt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
