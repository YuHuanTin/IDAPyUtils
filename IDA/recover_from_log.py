"""
Recover executed code from X64Dbg trace logs in IDA.

Run this script inside IDA. It parses run_mem.log-style lines such as:
    [exec] 0x7ff6e41747d4: push r15
    [block] 0x7ff6e402b9e0 id=8342
    [leave-ret] 0x7ff6e3f2a682

For every traced address that belongs to the current IDB, it undefines data if
needed and creates code. It intentionally does not create functions.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import ida_auto
import ida_bytes
import ida_kernwin
import ida_segment
import idc

import utils_ida


LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'X64Dbg', 'run.log'))

TRACE_ADDR_RE = re.compile(
    r'^\[(?:exec|jcc|call|ret|block|leave-ret|leave-usercode|leave-runtime)\]\s+'
    r'(?:ret=)?(0x[0-9a-fA-F]+)'
)
BLOCK_RANGE_RE = re.compile(r'^\[fault-block\]\s+id=\d+\s+(0x[0-9a-fA-F]+)\s+->\s+(0x[0-9a-fA-F]+)')
CALL_RE = re.compile(r'^\[call\]\s+call=(0x[0-9a-fA-F]+)\s+ret=(0x[0-9a-fA-F]+)')
RET_LINE_RE = re.compile(r'^\[ret\]\s+ret=(0x[0-9a-fA-F]+).*return_to=(0x[0-9a-fA-F]+)')
EXEC_RE = re.compile(r'^\[exec\]\s+(0x[0-9a-fA-F]+):\s+([a-zA-Z.]+)\s*(.*)$')
JCC_RE = re.compile(r'^\[jcc\]\s+(0x[0-9a-fA-F]+):\s+([a-zA-Z.]+)\s*(.*?)(?:\s+regs=.*)?$')
CALL_TARGET_RE = re.compile(r'\btarget=(0x[0-9a-fA-F]+)')
BLOCK_RE = re.compile(r'^\[block\]\s+(0x[0-9a-fA-F]+)\s+id=')


@dataclass(frozen=True)
class TraceInfo:
    code_addrs: set[int]
    ranges: list[tuple[int, int]]
    crefs: set[tuple[int, int, utils_ida.TypeOfXref]]


def _parse_int(text: str) -> int:
    return int(text, 16)


def _in_idb(ea: int) -> bool:
    return ida_segment.getseg(ea) is not None


def xref_type_for_mnemonic(mnemonic: str, is_call_target: bool = False) -> utils_ida.TypeOfXref:
    if is_call_target or mnemonic == 'call':
        return utils_ida.TypeOfXref.CALL_FAR
    if mnemonic.startswith('j'):
        return utils_ida.TypeOfXref.JMP_FAR
    return utils_ida.TypeOfXref.NORMAL


def record_trace_cref(crefs: set[tuple[int, int, utils_ida.TypeOfXref]], from_ea: int, to_ea: int,
                      cref_type: utils_ida.TypeOfXref) -> None:
    if from_ea and to_ea and from_ea != to_ea and _in_idb(from_ea) and _in_idb(to_ea):
        crefs.add((from_ea, to_ea, cref_type))


def parse_trace_log(path: str) -> TraceInfo:
    code_addrs: set[int] = set()
    ranges: list[tuple[int, int]] = []
    crefs: set[tuple[int, int, utils_ida.TypeOfXref]] = set()
    prev_ea = 0
    prev_mnemonic = ''

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = EXEC_RE.match(line)
            if m:
                ea = _parse_int(m.group(1))
                mnemonic = m.group(2).lower()
                op_text = m.group(3)
                code_addrs.add(ea)
                if prev_ea and prev_mnemonic.startswith('j'):
                    record_trace_cref(crefs, prev_ea, ea, utils_ida.TypeOfXref.JMP_FAR)
                target = CALL_TARGET_RE.search(op_text)
                if target and mnemonic == 'call':
                    target_ea = _parse_int(target.group(1))
                    if _in_idb(target_ea):
                        code_addrs.add(target_ea)
                        record_trace_cref(crefs, ea, target_ea, utils_ida.TypeOfXref.CALL_FAR)
                prev_ea = ea
                prev_mnemonic = mnemonic
                continue

            m = JCC_RE.match(line)
            if m:
                ea = _parse_int(m.group(1))
                mnemonic = m.group(2).lower()
                code_addrs.add(ea)
                prev_ea = ea
                prev_mnemonic = mnemonic
                continue

            m = BLOCK_RE.match(line)
            if m:
                ea = _parse_int(m.group(1))
                code_addrs.add(ea)
                if prev_ea and prev_mnemonic.startswith('j'):
                    record_trace_cref(crefs, prev_ea, ea, utils_ida.TypeOfXref.JMP_FAR)
                prev_ea = ea
                prev_mnemonic = ''
                continue

            m = TRACE_ADDR_RE.match(line)
            if m:
                ea = _parse_int(m.group(1))
                code_addrs.add(ea)
                continue

            m = BLOCK_RANGE_RE.match(line)
            if m:
                start = _parse_int(m.group(1))
                end = _parse_int(m.group(2))
                if end >= start:
                    ranges.append((start, end))
                    code_addrs.add(start)
                    code_addrs.add(end)
                continue

            m = CALL_RE.match(line)
            if m:
                call_ea = _parse_int(m.group(1))
                ret_ea = _parse_int(m.group(2))
                code_addrs.add(call_ea)
                code_addrs.add(ret_ea)
                continue

            m = RET_LINE_RE.match(line)
            if m:
                ret_ea = _parse_int(m.group(1))
                return_to = _parse_int(m.group(2))
                code_addrs.add(ret_ea)
                if return_to:
                    code_addrs.add(return_to)

    return TraceInfo(code_addrs=code_addrs, ranges=ranges, crefs=crefs)


def get_item_range(ea: int) -> tuple[int, int]:
    start = ida_bytes.get_item_head(ea)
    end = ida_bytes.get_item_end(ea)
    if start == idc.BADADDR or end == idc.BADADDR or end <= start:
        return ea, ea + 1
    return start, end


def AsCode(ea: int, size: int | None = None) -> bool:
    if not _in_idb(ea):
        return False

    if utils_ida.IsCode(ea):
        return True

    item_start, item_end = get_item_range(ea)
    item_size = max(1, item_end - item_start)
    if size is None:
        size = item_size

    print(f'{hex(ea)} is not code, be code')
    utils_ida.DelItem(item_start, max(size, item_size))
    return bool(utils_ida.CreateInst(ea))


def next_code_candidate(ea: int, end: int) -> int:
    item_size = ida_bytes.get_item_size(ea)
    if item_size > 0:
        return ea + item_size
    next_ea = idc.next_head(ea, end + 1)
    if next_ea != idc.BADADDR and next_ea > ea:
        return next_ea
    return ea + 1


def recover_range(start: int, end: int) -> int:
    made = 0
    ea = start
    while ea <= end and _in_idb(ea):
        if AsCode(ea):
            made += 1
            ea = next_code_candidate(ea, end)
        else:
            ea += 1
    return made


def create_trace_crefs(crefs: set[tuple[int, int, utils_ida.TypeOfXref]]) -> int:
    made = 0
    for from_ea, to_ea, cref_type in sorted(crefs):
        if not _in_idb(from_ea) or not _in_idb(to_ea):
            continue
        if not utils_ida.IsCode(from_ea) and not AsCode(from_ea):
            print(f'[recover-cref-skip] from is not code: {hex(from_ea)} -> {hex(to_ea)}')
            continue
        if not utils_ida.IsCode(to_ea) and not AsCode(to_ea):
            print(f'[recover-cref-skip] to is not code: {hex(from_ea)} -> {hex(to_ea)}')
            continue
        if utils_ida.CreateCref(from_ea, to_ea, cref_type):
            made += 1
        else:
            print(f'[recover-cref-fail] {hex(from_ea)} -> {hex(to_ea)} type={cref_type.name}')
    return made


def recover(path: str = LOG_PATH) -> None:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    info = parse_trace_log(path)
    made = 0
    skipped = 0

    for ea in sorted(info.code_addrs):
        if AsCode(ea):
            made += 1
        else:
            skipped += 1

    for start, end in info.ranges:
        made += recover_range(start, end)

    ida_auto.auto_wait()
    crefs = create_trace_crefs(info.crefs)
    ida_auto.auto_wait()

    print(
        f'[recover-from-log] path={path} code_addrs={len(info.code_addrs)} '
        f'ranges={len(info.ranges)} made={made} crefs={crefs} skipped={skipped}'
    )


def main() -> None:
    path = LOG_PATH
    if not os.path.exists(path):
        chosen = ida_kernwin.ask_file(False, '*.log', 'Select trace log')
        if not chosen:
            print('[recover-from-log] canceled')
            return
        path = chosen
    recover(path)


if __name__ == '__main__':
    main()
