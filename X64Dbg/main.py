import contextlib
import os
import sys
import traceback
from dataclasses import dataclass, field

import capstone
import unicorn
import x64dbg_automate
from x64dbg_automate.models import Breakpoint, BreakpointType, DebugSession, MemPage

from Simulate import utils_uc

X64DBG_PATH = r"x64dbg.exe"
STACK_EXTRA = 0x10000
USER_CODE_INFO = 'calc'
LOG_TO_FILE = True
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'run.log')
API_PARAMS_FILE = os.path.join(os.path.dirname(__file__), 'apis.txt')
LOG_EXEC = True
LOG_UC_MAP = False
USE_BLOCK_CACHE = True
CHKSTK_OFFSET = 0x4decf0
SYNC_ON_MEM_READ = True
LOG_MEM_ACCESS = False
LOG_MEM_CACHE = False
SYNC_GUARD_DEPTH = 0

@contextlib.contextmanager
def redirect_stdout_stderr_to_file(enabled: bool, path: str):
    if not enabled:
        yield None
        return

    with open(path, 'w', encoding='utf-8', buffering=100 * 1024 * 1024) as f:
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            yield f

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

REGS64 = [
    ('rax', unicorn.x86_const.UC_X86_REG_RAX),
    ('rbx', unicorn.x86_const.UC_X86_REG_RBX),
    ('rcx', unicorn.x86_const.UC_X86_REG_RCX),
    ('rdx', unicorn.x86_const.UC_X86_REG_RDX),
    ('rbp', unicorn.x86_const.UC_X86_REG_RBP),
    ('rsp', unicorn.x86_const.UC_X86_REG_RSP),
    ('rsi', unicorn.x86_const.UC_X86_REG_RSI),
    ('rdi', unicorn.x86_const.UC_X86_REG_RDI),
    ('r8', unicorn.x86_const.UC_X86_REG_R8),
    ('r9', unicorn.x86_const.UC_X86_REG_R9),
    ('r10', unicorn.x86_const.UC_X86_REG_R10),
    ('r11', unicorn.x86_const.UC_X86_REG_R11),
    ('r12', unicorn.x86_const.UC_X86_REG_R12),
    ('r13', unicorn.x86_const.UC_X86_REG_R13),
    ('r14', unicorn.x86_const.UC_X86_REG_R14),
    ('r15', unicorn.x86_const.UC_X86_REG_R15),
    ('rip', unicorn.x86_const.UC_X86_REG_RIP),
]
RFLAGS_TF = 0x100
PAGE_SIZE = 0x1000
MANAGED_BP_PREFIX = 'codex_tmp_'

def GetClient() -> x64dbg_automate.X64DbgClient:
    client = x64dbg_automate.X64DbgClient(X64DBG_PATH)
    sessions: list[DebugSession] = x64dbg_automate.X64DbgClient.list_sessions()
    if not sessions:
        raise RuntimeError('No x64dbg Automate session found')

    session = sessions[0]
    client.attach_session(session.pid)
    print(f'[x64dbg] attach session pid={session.pid}')
    return client

def FindMemPage(client: x64dbg_automate.X64DbgClient, addr: int) -> MemPage | None:
    for page in client.memmap():
        if page.base_address <= addr < page.base_address + page.region_size:
            return page
    return None

def IsPotentialUserPtr(addr: int) -> bool:
    return 0x10000 <= addr < 0x800000000000

def IsReadableX64DbgPtr(client: x64dbg_automate.X64DbgClient, addr: int) -> bool:
    return bool(IsPotentialUserPtr(addr) and FindMemPage(client, addr) is not None)

def GetUserCodeRange(client: x64dbg_automate.X64DbgClient, rip: int) -> tuple[int, int]:
    pages = client.memmap()
    bases = set()
    for page in pages:
        if USER_CODE_INFO and USER_CODE_INFO.lower() in page.info.lower():
            bases.add(page.allocation_base)

    if not bases:
        rip_page = FindMemPage(client, rip)
        if rip_page is None:
            raise RuntimeError(f'RIP page not found: {hex(rip)}')
        bases.add(rip_page.allocation_base)

    ranges = []
    for page in pages:
        if page.allocation_base in bases:
            ranges.append((page.base_address, page.base_address + page.region_size))

    return min(start for start, _ in ranges), max(end for _, end in ranges)

def IsInRange(addr: int, start: int, end: int) -> bool:
    return start <= addr < end

def IsRangeOverlap(start: int, end: int, other_start: int, other_end: int) -> bool:
    return start < other_end and other_start < end

def IsTraceAddress(state, addr: int) -> bool:
    return any(start <= addr < end for start, end in state.get('trace_ranges', []))

def AddTraceRange(state, start: int, end: int, reason: str) -> None:
    if end <= start:
        return
    ranges = state.setdefault('trace_ranges', [])
    ranges.append((start, end))
    state['trace_ranges'] = MergeRanges(ranges)
    print(f'[trace-range] {hex(start)}-{hex(end)} reason={reason}')

def AddTraceRangeForAddress(client: x64dbg_automate.X64DbgClient, state, addr: int, reason: str) -> bool:
    if not IsPotentialUserPtr(addr):
        return False
    page = FindMemPage(client, addr)
    if page is None:
        start = utils_uc.AlignDown(addr)
        end = start + PAGE_SIZE
    else:
        start = page.base_address
        end = page.base_address + page.region_size
    AddTraceRange(state, start, end, reason)
    return True

def IsChkstk(addr: int, user_start: int) -> bool:
    return addr == user_start + CHKSTK_OFFSET

def GetCallTarget(insn: capstone.CsInsn) -> int | None:
    if insn.mnemonic != 'call' or not insn.operands:
        return None
    op = insn.operands[0]
    return op.imm if op.type == capstone.x86_const.X86_OP_IMM else None

def GetX64DbgBreakpointsAt(client: x64dbg_automate.X64DbgClient, addr: int) -> list[Breakpoint]:
    bp_types = (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory)
    result: list[Breakpoint] = []
    for bp_type in bp_types:
        result.extend(bp for bp in client.get_breakpoints(bp_type) if bp.addr == addr)
    return result

def IsManagedBreakpoint(bp: Breakpoint) -> bool:
    return bp.name.startswith(MANAGED_BP_PREFIX)

def GetManagedBreakpointName(addr: int) -> str:
    return f'{MANAGED_BP_PREFIX}{addr:x}'

def HasX64DbgBreakpoint(client: x64dbg_automate.X64DbgClient, addr: int) -> bool:
    return bool(GetX64DbgBreakpointsAt(client, addr))

def SetX64DbgBreakpoint(client: x64dbg_automate.X64DbgClient, addr: int) -> None:
    breakpoints = GetX64DbgBreakpointsAt(client, addr)
    if breakpoints:
        states = ','.join(
            f'{bp.name}:enabled={int(bp.enabled)} active={int(bp.active)} singleshoot={int(bp.singleshoot)}'
            for bp in breakpoints)
        if any(bp.enabled and bp.active for bp in breakpoints):
            print(f'[x64dbg-bp-exists] {hex(addr)} {states}')
            return
        managed = [bp for bp in breakpoints if IsManagedBreakpoint(bp)]
        if managed:
            print(f'[x64dbg-bp-refresh] {hex(addr)} {states}')
            for bp in managed:
                client.clear_breakpoint(bp.name)
        else:
            print(f'[x64dbg-bp-reuse] {hex(addr)} {states}')
    name = GetManagedBreakpointName(addr)
    if client.set_breakpoint(addr, name=name, singleshoot=True):
        print(f'[x64dbg-bp] {hex(addr)} name={name}')
    else:
        print(f'[x64dbg-bp-fail] {hex(addr)} name={name}')

def ClearManagedBreakpoints(client: x64dbg_automate.X64DbgClient) -> None:
    cleared = 0
    for bp_type in (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory):
        for bp in client.get_breakpoints(bp_type):
            if not IsManagedBreakpoint(bp):
                continue
            if client.clear_breakpoint(bp.name):
                cleared += 1
    if cleared:
        print(f'[x64dbg-bp-cleanup] cleared={cleared}')

def GetSymbolLabel(client: x64dbg_automate.X64DbgClient, addr: int) -> str:
    sym = client.get_symbol_at(addr)
    if sym is not None:
        name = sym.undecoratedSymbol or sym.decoratedSymbol
        if name:
            return name
    label = client.get_label_at(addr)
    if label:
        return label
    comment = client.get_comment_at(addr)
    if comment:
        return comment
    page = FindMemPage(client, addr)
    return f'{page.info}!{addr:x}' if page else hex(addr)

def FatalExit(client: x64dbg_automate.X64DbgClient | None, uc: unicorn.Uc | None, message: str, code: int = 1,
              state=None) -> None:
    print(message)
    if uc is not None:
        if state is not None:
            DumpFaultBlock(uc, state)
        DumpStopState(uc)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)

def RunX64DbgToBreakpoint(client: x64dbg_automate.X64DbgClient, addr: int) -> int:
    SetX64DbgBreakpoint(client, addr)
    client.go(pass_exceptions=True)
    client.wait_until_stopped()
    return client.get_reg('rip')

def RunX64DbgUntil(client: x64dbg_automate.X64DbgClient, addr: int) -> bool:
    if client.get_reg('rip') == addr:
        return True
    rip = RunX64DbgToBreakpoint(client, addr)
    if rip == addr:
        return True
    print(f'[x64dbg-external-stop] expected {hex(addr)}, current {hex(rip)}')
    return False

def RunX64DbgUntilContext(client: x64dbg_automate.X64DbgClient, addr: int, expected_rsp: int | None,
                          reason: str, max_hits: int = 64) -> bool:
    for i in range(max_hits):
        rip = client.get_reg('rip')
        if rip != addr:
            rip = RunX64DbgToBreakpoint(client, addr)
            if rip != addr:
                print(f'[x64dbg-external-stop] reason={reason} expected {hex(addr)}, current {hex(rip)}')
                return False

        rsp = client.get_reg('rsp')
        if expected_rsp is None or rsp == expected_rsp:
            return True

        print(
            f'[x64dbg-context-skip] reason={reason} rip={hex(addr)} rsp={hex(rsp)} expected_rsp={hex(expected_rsp)} hit={i + 1}')
        StepX64DbgOnce(client)
    return False

def RunX64DbgUntilUserCode(client: x64dbg_automate.X64DbgClient, user_start: int, user_end: int,
                           max_stops: int = 64) -> bool:
    rip = client.get_reg('rip')
    if IsInRange(rip, user_start, user_end):
        return True
    if not client.is_debugging():
        return False

    print(f'[x64dbg-context-wait] stop=0 rip={hex(rip)} label={GetSymbolLabel(client, rip)}')
    client.go(pass_exceptions=True)
    client.wait_until_stopped()
    rip = client.get_reg('rip')
    print(f'[x64dbg-context-wait] stop=1 rip={hex(rip)} label={GetSymbolLabel(client, rip)}')
    return IsInRange(rip, user_start, user_end) and client.is_debugging()

def StepX64DbgOnce(client: x64dbg_automate.X64DbgClient) -> None:
    client.stepi(pass_exceptions=True)
    client.wait_until_stopped()

def RunX64DbgUntilApiCall(client: x64dbg_automate.X64DbgClient, api_addr: int, expected_ret: int,
                          max_hits: int = 32) -> bool:
    for i in range(max_hits):
        rip = RunX64DbgToBreakpoint(client, api_addr)
        if rip != api_addr:
            print(f'[x64dbg-external-stop] expected {hex(api_addr)}, current {hex(rip)}')
            return False
        actual_ret = ReadX64DbgU64(client, client.get_reg('rsp'))
        if actual_ret == expected_ret:
            return True
        print(f'[x64dbg-skip-hit] {hex(api_addr)} ret={hex(actual_ret)} expected={hex(expected_ret)} hit={i + 1}')
        StepX64DbgOnce(client)
    return False

def ReadX64DbgU64(client: x64dbg_automate.X64DbgClient, addr: int) -> int:
    return int.from_bytes(client.read_memory(addr, 8), 'little')

def ReadX64DbgU32(client: x64dbg_automate.X64DbgClient, addr: int) -> int:
    return int.from_bytes(client.read_memory(addr, 4), 'little')

def TryReadX64DbgU32(client: x64dbg_automate.X64DbgClient, addr: int) -> int | None:
    try:
        return ReadX64DbgU32(client, addr)
    except Exception as exc:
        print(f'[x64dbg-read-skip] u32 {hex(addr)}: {exc}')
        return None

def TryReadX64DbgU64(client: x64dbg_automate.X64DbgClient, addr: int) -> int | None:
    try:
        return ReadX64DbgU64(client, addr)
    except Exception as exc:
        print(f'[x64dbg-read-skip] u64 {hex(addr)}: {exc}')
        return None

def ReadX64DbgAnsi(client: x64dbg_automate.X64DbgClient, addr: int, limit: int = 256) -> str:
    data = bytearray()
    for offset in range(limit):
        try:
            ch = client.read_memory(addr + offset, 1)
        except Exception:
            return ''
        if ch == b'\x00':
            break
        data.extend(ch)
    return data.decode('mbcs', errors='ignore')

def ReadX64DbgUtf16(client: x64dbg_automate.X64DbgClient, addr: int, limit: int = 256) -> str:
    data = bytearray()
    for offset in range(0, limit * 2, 2):
        try:
            ch = client.read_memory(addr + offset, 2)
        except Exception:
            return ''
        if ch == b'\x00\x00':
            break
        data.extend(ch)
    return data.decode('utf-16le', errors='ignore')

def ReadX64DbgCStringLen(client: x64dbg_automate.X64DbgClient, addr: int, limit: int = 0x1000) -> int:
    for offset in range(limit):
        try:
            if client.read_memory(addr + offset, 1) == b'\x00':
                return offset + 1
        except Exception:
            break
    return 0

def ReadX64DbgWStringLen(client: x64dbg_automate.X64DbgClient, addr: int, limit: int = 0x1000) -> int:
    for offset in range(0, limit * 2, 2):
        try:
            if client.read_memory(addr + offset, 2) == b'\x00\x00':
                return offset + 2
        except Exception:
            break
    return 0

def ReadX64DbgStackArg(client: x64dbg_automate.X64DbgClient, api_rsp: int, index: int) -> int:
    return ReadX64DbgU64(client, api_rsp + 0x28 + index * 8)

def ReadApiRegs(client: x64dbg_automate.X64DbgClient) -> dict[str, int]:
    return {name: client.get_reg(name) for name, _ in REGS64}

def ReadApiArgs(client: x64dbg_automate.X64DbgClient, api_rsp: int, api_label: str, default_count: int = 8) -> tuple[
    int, ...]:
    spec = ApiSyncLayer._find_param_spec(api_label)
    count = max(default_count, len(spec.types) if spec is not None else 0)
    values = []
    regs = ReadApiRegs(client)
    for index in range(count):
        if index < 4:
            values.append(regs[('rcx', 'rdx', 'r8', 'r9')[index]])
        else:
            values.append(ReadX64DbgStackArg(client, api_rsp, index - 4))
    return tuple(values)

def IsSwitchToFiberApi(api_label: str) -> bool:
    return 'switchtofiber' in NormalizeApiName(api_label)

def IsConvertThreadToFiberApi(api_label: str) -> bool:
    name = NormalizeApiName(api_label)
    return name in {'convertthreadtofiber', 'convertthreadtofiberex'} or name.endswith(
        'convertthreadtofiber') or name.endswith('convertthreadtofiberex')

def IsCreateFiberApi(api_label: str) -> bool:
    name = NormalizeApiName(api_label)
    return name in {'createfiber', 'createfiberex'} or name.endswith('createfiber') or name.endswith('createfiberex')

@dataclass(slots=True)
class ApiSnapshot:
    rip: int
    rsp: int
    ret_addr: int
    label: str
    regs: dict[str, int]
    args: tuple[int, ...]

@dataclass(slots=True)
class FiberTraceState:
    handle: int
    start_address: int = 0
    parameter: int = 0
    resume_rip: int = 0
    call_stack: list[tuple[int, int]] = field(default_factory=list)
    entered: bool = False
    switch_count: int = 0

@dataclass(slots=True)
class ApiParamSpec:
    name: str
    types: list[str]
    meta: list[dict[str, str]]
    ret_type: str | None = None
    ret_meta: dict[str, str] | None = None

API_ARG_BASE_TYPES = {'cstr', 'wstr', 'u32ptr', 'u64ptr', 'u32', 'u64'}

def NormalizeApiName(name: str) -> str:
    name = name.strip()
    if name.startswith('<') and name.endswith('>'):
        name = name[1:-1]
    name = name.split('!')[-1].strip()
    if name.startswith('__imp_'):
        name = name[6:]
    return name.lower()

def ParseApiArgSpec(text: str) -> tuple[str, dict[str, str]]:
    typ, sep, rest = text.partition('(')
    meta = {}
    if sep and rest.endswith(')'):
        for item in rest[:-1].split(';'):
            key, eq, value = item.strip().partition('=')
            if eq:
                meta[key.strip().lower()] = value.strip().lower()
    return typ.strip(), meta

def SplitTopLevel(text: str, sep: str) -> list[str]:
    parts = []
    depth = 0
    start = 0
    for index, ch in enumerate(text):
        if ch == '(':
            depth += 1
        elif ch == ')' and depth:
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts

def ApiSyncLayerBaseType(arg_type: str) -> str:
    typ = arg_type.lower()
    return typ[:-4] if typ.endswith('_out') else typ

def LoadApiParamSpecs(path: str) -> dict[str, ApiParamSpec]:
    specs: dict[str, ApiParamSpec] = {}
    if not os.path.exists(path):
        print(f'[api-spec-missing] {path}')
        return specs
    with open(path, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            name, sep, rest = line.partition(':')
            if not sep:
                print(f'[api-spec-skip] line={line_no} text={line}')
                continue
            sections = [part.strip() for part in SplitTopLevel(rest, ';') if part.strip()]
            if len(sections) > 2:
                print(f'[api-spec-skip] line={line_no} too many sections={sections}')
                continue

            args_text = sections[0] if sections else ''
            ret_spec = sections[1] if len(sections) == 2 else None
            parts = [part.strip() for part in args_text.replace('，', ',').split(',') if part.strip()]
            if not parts:
                count = 0
                raw_types = []
            else:
                try:
                    count = int(parts[0], 0)
                except ValueError:
                    print(f'[api-spec-skip] line={line_no} bad count={parts[0]}')
                    continue
                raw_types = parts[1:]
            if len(raw_types) < count:
                raw_types.extend(['u64'] * (count - len(raw_types)))
            arg_specs = raw_types[:count]
            if len(raw_types) > count:
                print(f'[api-spec-skip] line={line_no} too many arg specs={raw_types[count:]}')
                continue
            parsed = [ParseApiArgSpec(typ) for typ in arg_specs]
            types = [typ for typ, _ in parsed]
            meta = [arg_meta for _, arg_meta in parsed]
            bad_type = next((typ for typ in types if ApiSyncLayerBaseType(typ) not in API_ARG_BASE_TYPES), None)
            if bad_type is not None:
                print(f'[api-spec-skip] line={line_no} bad type={bad_type}')
                continue
            ret_meta = None
            ret_type = None
            if ret_spec:
                ret_type, ret_meta = ParseApiArgSpec(ret_spec)
                if ApiSyncLayerBaseType(ret_type) not in API_ARG_BASE_TYPES:
                    print(f'[api-spec-skip] line={line_no} bad ret spec={ret_spec}')
                    continue
            specs[NormalizeApiName(name)] = ApiParamSpec(name.strip(), types, meta, ret_type, ret_meta)
    print(f'[api-spec] loaded {len(specs)} entries from {path}')
    return specs

API_PARAM_SPECS: dict[str, ApiParamSpec] | None = None

def GetApiParamSpecs() -> dict[str, ApiParamSpec]:
    global API_PARAM_SPECS
    if API_PARAM_SPECS is None:
        API_PARAM_SPECS = LoadApiParamSpecs(API_PARAMS_FILE)
    return API_PARAM_SPECS

class ApiSyncLayer:
    @staticmethod
    def format_args(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot) -> str:
        spec = ApiSyncLayer._find_param_spec(snap.label)
        if spec is None:
            return ApiSyncLayer._format_raw_args(snap)

        parts = []
        for index, arg_type in enumerate(spec.types):
            value = ApiSyncLayer._read_arg(snap, index)
            arg_name = ApiSyncLayer._arg_name(index)
            parts.append(
                f'{arg_name}:{arg_type}={hex(value)}{ApiSyncLayer._decode_typed_value(client, arg_type, value, snap, spec, index)}')
        for index in range(len(spec.types), len(snap.args)):
            parts.append(f'{ApiSyncLayer._arg_name(index)}={hex(ApiSyncLayer._read_arg(snap, index))}')
        return ', '.join(parts)

    @staticmethod
    def format_result(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, current_regs: dict[str, int]) -> str:
        parts = []
        spec = ApiSyncLayer._find_param_spec(snap.label)
        ret_text = ApiSyncLayer._format_return(client, spec, current_regs)
        if ret_text:
            parts.append(ret_text)
        if spec is not None:
            for index, arg_type in enumerate(spec.types):
                if not arg_type.lower().endswith('_out'):
                    continue
                value = ApiSyncLayer._read_arg(snap, index)
                if not IsPotentialUserPtr(value):
                    continue
                arg_name = ApiSyncLayer._arg_name(index)
                parts.append(
                    f'{arg_name}->{hex(value)}{ApiSyncLayer._decode_typed_value(client, arg_type, value, snap, spec, index)}')
        return ', '.join(parts)

    @staticmethod
    def _format_raw_args(snap: ApiSnapshot) -> str:
        return ', '.join(
            f'{ApiSyncLayer._arg_name(i)}={hex(value)}' for i, value in enumerate(snap.args))

    @staticmethod
    def _find_param_spec(api_label: str) -> ApiParamSpec | None:
        api_name = NormalizeApiName(api_label)
        specs = GetApiParamSpecs()
        if api_name in specs:
            return specs[api_name]
        for name, spec in specs.items():
            if name in api_name:
                return spec
        return None

    @staticmethod
    def _arg_name(index: int) -> str:
        return ('rcx', 'rdx', 'r8', 'r9')[index] if index < 4 else f'stack{index - 4}'

    @staticmethod
    def _read_arg(snap: ApiSnapshot, index: int) -> int:
        return snap.args[index] if 0 <= index < len(snap.args) else 0

    @staticmethod
    def _read_ret_value(current_regs: dict[str, int], ret_type: str) -> int:
        base_type = ApiSyncLayerBaseType(ret_type)
        value = current_regs.get('rax', 0)
        if base_type in {'u32', 'u32ptr'}:
            return value & 0xffffffff
        return value

    @staticmethod
    def _read_fixed_size(meta: dict[str, str]) -> int | None:
        text = meta.get('size')
        return ApiSyncLayer._parse_int(text) if text else None

    @staticmethod
    def _read_size_from_meta(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, spec: ApiParamSpec,
                             meta: dict[str, str]) -> int | None:
        size_from = meta.get('size_from')
        if not size_from:
            return None
        size_index = ApiSyncLayer._parse_arg_ref(size_from)
        if size_index is None or not 0 <= size_index < len(spec.types):
            return None
        size = ApiSyncLayer._read_size_arg(client, snap, spec, size_index, meta.get('size_type'))
        if size is None:
            return None
        return size

    @staticmethod
    def _read_size_arg(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, spec: ApiParamSpec, index: int,
                       size_type: str | None) -> int | None:
        value = ApiSyncLayer._read_arg(snap, index)
        arg_type = ApiSyncLayerBaseType(spec.types[index])
        read_type = ApiSyncLayerBaseType(size_type) if size_type else arg_type
        if arg_type in {'u32', 'u64'}:
            return value & 0xffffffff if read_type == 'u32' else value
        try:
            if read_type in {'u32', 'u32ptr'}:
                return ReadX64DbgU32(client, value)
            if read_type in {'u64', 'u64ptr'}:
                return ReadX64DbgU64(client, value)
        except Exception:
            return None
        return None

    @staticmethod
    def _parse_int(text: str | None, default: int | None = None) -> int | None:
        if text is None:
            return default
        try:
            return int(text, 0)
        except ValueError:
            return default

    @staticmethod
    def _parse_arg_ref(ref: str) -> int | None:
        if not ref.startswith('arg'):
            return None
        try:
            return int(ref[3:], 0) - 1
        except ValueError:
            return None

    @staticmethod
    def _decode_typed_value(client: x64dbg_automate.X64DbgClient, arg_type: str, value: int,
                            snap: ApiSnapshot | None = None, spec: ApiParamSpec | None = None,
                            index: int | None = None) -> str:
        if not value:
            return ''
        typ = ApiSyncLayerBaseType(arg_type)
        if typ == 'cstr':
            limit = ApiSyncLayer._resolve_read_limit(client, typ, value, snap, spec, index)
            text = ReadX64DbgAnsi(client, value, limit=limit) if IsReadableX64DbgPtr(client, value) else ''
            return f' "{text}"' if text else ''
        if typ == 'wstr':
            limit = ApiSyncLayer._resolve_read_limit(client, typ, value, snap, spec, index)
            text = ReadX64DbgUtf16(client, value, limit=limit) if IsReadableX64DbgPtr(client, value) else ''
            return f' "{text}"' if text else ''
        if typ == 'u32ptr':
            data = TryReadX64DbgU32(client, value) if IsReadableX64DbgPtr(client, value) else None
            return f' -> {hex(data)}' if data is not None else ''
        if typ == 'u64ptr':
            data = ApiSyncLayer._try_read_x64dbg_u64(client, value) if IsReadableX64DbgPtr(client, value) else None
            return f' -> {hex(data)}' if data is not None else ''
        return ''

    @staticmethod
    def _try_read_x64dbg_u64(client: x64dbg_automate.X64DbgClient, addr: int) -> int | None:
        try:
            return ReadX64DbgU64(client, addr)
        except Exception as exc:
            print(f'[x64dbg-read-skip] u64 {hex(addr)}: {exc}')
            return None

    @staticmethod
    def _resolve_read_limit(client: x64dbg_automate.X64DbgClient, base_type: str, value: int, snap: ApiSnapshot | None,
                            spec: ApiParamSpec | None, index: int | None) -> int:
        if snap is None or spec is None or index is None:
            return 0x1000 if base_type == 'cstr' else 0x800
        meta = spec.meta[index]
        size = ApiSyncLayer._read_fixed_size(meta)
        if size is None:
            size = ApiSyncLayer._read_size_from_meta(client, snap, spec, meta)
        if not size:
            if base_type == 'cstr':
                size = ReadX64DbgCStringLen(client, value) or 0x1000
            elif base_type == 'wstr':
                byte_size = ReadX64DbgWStringLen(client, value) or 0x1000
                size = max(1, byte_size // 2)
            else:
                size = 0x1000
        return max(1, size)

    @staticmethod
    def _format_return(client: x64dbg_automate.X64DbgClient, spec: ApiParamSpec | None,
                       current_regs: dict[str, int]) -> str:
        if spec is None or spec.ret_type is None:
            return ''
        value = ApiSyncLayer._read_ret_value(current_regs, spec.ret_type)
        text = f'return:{spec.ret_type}={hex(value)}'
        if spec.ret_type.lower().endswith('_out') and IsPotentialUserPtr(value):
            text += ApiSyncLayer._decode_typed_value(client, spec.ret_type, value, None, None, None)
        return text

def FindCurrentTeb(client: x64dbg_automate.X64DbgClient, rsp: int) -> tuple[MemPage, int]:
    teb_pages = [page for page in client.memmap() if 'teb' in page.info.lower()]
    for page in teb_pages:
        for teb_base in range(page.base_address, page.base_address + page.region_size, PAGE_SIZE):
            try:
                stack_base = ReadX64DbgU64(client, teb_base + 8)
                stack_limit = ReadX64DbgU64(client, teb_base + 0x10)
                self_ptr = ReadX64DbgU64(client, teb_base + 0x30)
            except Exception:
                continue
            if self_ptr == teb_base and stack_limit <= rsp <= stack_base:
                return page, teb_base
    for page in teb_pages:
        for teb_base in range(page.base_address, page.base_address + page.region_size, PAGE_SIZE):
            try:
                stack_base = ReadX64DbgU64(client, teb_base + 8)
                stack_limit = ReadX64DbgU64(client, teb_base + 0x10)
            except Exception:
                continue
            if stack_limit <= rsp <= stack_base:
                return page, teb_base
    raise RuntimeError('TEB page not found')

def MapTebMemory(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, rsp: int) -> None:
    teb_page, teb_base = FindCurrentTeb(client, rsp)
    if not MapPageFromX64Dbg(uc, client, teb_page):
        raise RuntimeError(f'TEB map failed: {hex(teb_page.base_address)}')
    uc.reg_write(unicorn.x86_const.UC_X86_REG_GS_BASE, teb_base)
    print(f'[uc-gs] base={hex(teb_base)}')

def EnsureStartInUserCode(client: x64dbg_automate.X64DbgClient, user_start: int, user_end: int) -> None:
    rip = client.get_reg('rip')
    if IsInRange(rip, user_start, user_end):
        return

    ret_addr = ReadX64DbgU64(client, client.get_reg('rsp'))
    label = GetSymbolLabel(client, rip)
    print(f'[start-api] {label} at {hex(rip)}, ret={hex(ret_addr)}')
    if not RunX64DbgUntil(client, ret_addr):
        current_rip = client.get_reg('rip')
        print(f'[x64dbg-warning] expected usercode ret {hex(ret_addr)}, current {hex(current_rip)}')

def MapPageFromX64Dbg(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, page: MemPage) -> bool:
    start = utils_uc.AlignDown(page.base_address)
    end = utils_uc.AlignUp(page.base_address + page.region_size)
    size = end - start
    try:
        data = client.read_memory(page.base_address, page.region_size)
    except Exception as exc:
        print(f'[uc-map-fail] {hex(page.base_address)}-{hex(page.base_address + page.region_size)} {page.info}: {exc}')
        return False

    try:
        uc.mem_map(start, size)
    except unicorn.UcError:
        pass
    uc.mem_write(page.base_address, data)
    if LOG_UC_MAP:
        print(f'[uc-map] {hex(page.base_address)}-{hex(page.base_address + page.region_size)} {page.info}')
    return True

def IsUcMapped(uc: unicorn.Uc, addr: int, size: int = 1) -> bool:
    try:
        uc.mem_read(addr, size)
        return True
    except unicorn.UcError:
        return False

@contextlib.contextmanager
def UcSyncGuard(state=None):
    global SYNC_GUARD_DEPTH
    SYNC_GUARD_DEPTH += 1
    if state is not None:
        state['sync_depth'] = state.get('sync_depth', 0) + 1
    try:
        yield
    finally:
        if state is not None:
            state['sync_depth'] = max(0, state.get('sync_depth', 0) - 1)
        SYNC_GUARD_DEPTH = max(0, SYNC_GUARD_DEPTH - 1)

def IsUcSyncing(state=None) -> bool:
    return SYNC_GUARD_DEPTH > 0 or bool(state is not None and state.get('sync_depth', 0))

def IsInvalidWriteAccess(access: int) -> bool:
    return access in {
        getattr(unicorn, 'UC_MEM_WRITE', -1),
        getattr(unicorn, 'UC_MEM_WRITE_UNMAPPED', -1),
        getattr(unicorn, 'UC_MEM_WRITE_PROT', -1),
    }

def MergeRanges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted((start, end) for start, end in ranges if end > start)
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]

def GetDirtyRanges(state, start: int, end: int) -> list[tuple[int, int]]:
    if state is None:
        return []
    ranges = []
    for dirty_start, dirty_end in state.get('uc_dirty_ranges', []):
        overlap_start = max(start, dirty_start)
        overlap_end = min(end, dirty_end)
        if overlap_end > overlap_start:
            ranges.append((overlap_start, overlap_end))
    return MergeRanges(ranges)

def GetCleanRanges(state, start: int, end: int) -> list[tuple[int, int]]:
    dirty_ranges = GetDirtyRanges(state, start, end)
    clean_ranges = []
    cur = start
    for dirty_start, dirty_end in dirty_ranges:
        if cur < dirty_start:
            clean_ranges.append((cur, dirty_start))
        cur = max(cur, dirty_end)
    if cur < end:
        clean_ranges.append((cur, end))
    return clean_ranges

class MemSyncManager:
    def __init__(self, uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, state) -> None:
        self.uc = uc
        self.client = client
        self.state = state
        self.page_cache: dict[int, bytes] = {}
        self.page_info_cache: dict[int, str] = {}
        self.read_fail_cache: set[int] = set()
        self.blank_page = bytes(PAGE_SIZE)
        self.stats = {
            'xdbg_reads': 0,
            'cache_hits': 0,
            'refreshes': 0,
            'preserved_refreshes': 0,
            'accesses': 0,
            'dirty_skips': 0,
        }

    def reset_after_xdbg_run(self, reason: str) -> None:
        try:
            self.client.gui_refresh_views()
        except Exception as exc:
            print(f'[x64dbg-refresh-fail] {exc}')
        self.invalidate_all(reason)
        self.state['uc_dirty_ranges'].clear()
        print(f'[mem-sync-reset] reason={reason}')

    def invalidate_all(self, reason: str) -> None:
        pages = len(self.page_cache)
        fails = len(self.read_fail_cache)
        self.page_cache.clear()
        self.page_info_cache.clear()
        self.read_fail_cache.clear()
        print(f'[mem-cache-clear] reason={reason} pages={pages} fails={fails}')

    def before_access(self, address: int, size: int, kind: str, value: int = 0) -> bool:
        if IsUcSyncing(self.state):
            return True
        if size <= 0:
            size = 1
        if not IsPotentialUserPtr(address):
            return False

        self.stats['accesses'] += 1
        if LOG_MEM_ACCESS:
            suffix = f' value={hex(value)}' if kind == 'write' else ''
            print(f'[mem-{kind}] addr={hex(address)} size={size}{suffix}')

        ok = True
        end = address + size
        cur = address
        while cur < end:
            page_base = utils_uc.AlignDown(cur)
            chunk_end = min(end, page_base + PAGE_SIZE)
            if not self._sync_page_for_access(page_base, cur, chunk_end, kind):
                ok = False
            cur = chunk_end
        return ok

    def map_page_for_invalid(self, address: int, access: int) -> bool:
        page_base = utils_uc.AlignDown(address)
        xdbg_bytes = self._read_xdbg_page(page_base, force=True)
        if xdbg_bytes is None and not IsInvalidWriteAccess(access):
            return False
        with UcSyncGuard(self.state):
            EnsureUcMappedRange(self.uc, page_base, page_base + PAGE_SIZE)
            try:
                if xdbg_bytes is None:
                    self.uc.mem_write(page_base, self.blank_page)
                    print(f'[mem-invalid-blank] access={access} page={hex(page_base)}')
                else:
                    self.uc.mem_write(page_base, xdbg_bytes)
            except unicorn.UcError as exc:
                print(f'[mem-invalid-map-fail] page={hex(page_base)}: {exc}')
                return False
        MarkRangeClean(self.state, page_base, page_base + PAGE_SIZE)
        print(f'[mem-invalid-map] page={hex(page_base)} info={self.page_info_cache.get(page_base, "?")}')
        return True

    def _sync_page_for_access(self, page_base: int, start: int, end: int, kind: str) -> bool:
        xdbg_bytes = self._read_xdbg_page(page_base)
        if xdbg_bytes is None:
            return False

        with UcSyncGuard(self.state):
            EnsureUcMappedRange(self.uc, page_base, page_base + PAGE_SIZE)
            try:
                uc_bytes = bytes(self.uc.mem_read(page_base, PAGE_SIZE))
            except unicorn.UcError as exc:
                print(f'[mem-uc-read-fail] page={hex(page_base)}: {exc}')
                return False

        dirty_ranges = GetDirtyRanges(self.state, page_base, page_base + PAGE_SIZE)
        mismatch = uc_bytes != xdbg_bytes
        mismatch_at = start if mismatch else 0

        if not mismatch:
            if LOG_MEM_CACHE:
                print(f'[mem-sync-ok] {kind} {hex(start)}-{hex(end)} page={hex(page_base)}')
            return True

        return self._refresh_page(page_base, uc_bytes, xdbg_bytes, reason=f'{kind}@{hex(mismatch_at)}',
                                  dirty_ranges=dirty_ranges)

    def _refresh_page(self, page_base: int, uc_bytes: bytes, xdbg_bytes: bytes, reason: str, dirty_ranges=None) -> bool:
        if dirty_ranges is None:
            dirty_ranges = GetDirtyRanges(self.state, page_base, page_base + PAGE_SIZE)
        merged = bytearray(xdbg_bytes)
        preserved = 0
        for dirty_start, dirty_end in dirty_ranges:
            rel_start = dirty_start - page_base
            rel_end = dirty_end - page_base
            merged[rel_start:rel_end] = uc_bytes[rel_start:rel_end]
            preserved += dirty_end - dirty_start

        with UcSyncGuard(self.state):
            EnsureUcMappedRange(self.uc, page_base, page_base + PAGE_SIZE)
            try:
                self.uc.mem_write(page_base, bytes(merged))
            except unicorn.UcError as exc:
                print(f'[mem-refresh-fail] page={hex(page_base)} reason={reason}: {exc}')
                return False

        self.stats['refreshes'] += 1
        if preserved:
            self.stats['preserved_refreshes'] += 1
            print(
                f'[mem-refresh-preserve] page={hex(page_base)} preserved={preserved} reason={reason} info={self.page_info_cache.get(page_base, "?")}')
        else:
            MarkRangeClean(self.state, page_base, page_base + PAGE_SIZE)
            print(
                f'[mem-refresh] page={hex(page_base)} reason={reason} info={self.page_info_cache.get(page_base, "?")}')
        return True

    def _read_xdbg_page(self, page_base: int, force: bool = False) -> bytes | None:
        if not force and page_base in self.page_cache:
            self.stats['cache_hits'] += 1
            return self.page_cache[page_base]
        if not force and page_base in self.read_fail_cache:
            return None

        page = FindMemPage(self.client, page_base)
        if page is None:
            # The address may still be inside a region that starts after page_base.
            page = FindMemPage(self.client, page_base + PAGE_SIZE - 1)
        if page is not None:
            read_start = max(page_base, page.base_address)
            read_end = min(page_base + PAGE_SIZE, page.base_address + page.region_size)
        else:
            read_start = page_base
            read_end = page_base + PAGE_SIZE

        if read_end <= read_start:
            self.read_fail_cache.add(page_base)
            print(f'[mem-xdbg-empty] page={hex(page_base)} info={page.info if page is not None else "?"}')
            return None

        try:
            data = self.client.read_memory(read_start, read_end - read_start)
        except Exception as exc:
            self.read_fail_cache.add(page_base)
            info = page.info if page is not None else 'direct'
            print(f'[mem-xdbg-read-fail] {hex(read_start)}-{hex(read_end)} {info}: {exc}')
            return None

        buf = bytearray(PAGE_SIZE)
        rel = read_start - page_base
        buf[rel:rel + len(data)] = data
        self.page_cache[page_base] = bytes(buf)
        self.page_info_cache[page_base] = page.info if page is not None else 'direct'
        self.stats['xdbg_reads'] += 1
        if LOG_MEM_CACHE:
            info = page.info if page is not None else 'direct'
            print(f'[mem-xdbg-read] page={hex(page_base)} range={hex(read_start)}-{hex(read_end)} info={info}')
        return self.page_cache[page_base]

def EnsureUcMappedRange(uc: unicorn.Uc, start: int, end: int) -> None:
    for page in range(utils_uc.AlignDown(start), utils_uc.AlignUp(end), PAGE_SIZE):
        try:
            uc.mem_map(page, PAGE_SIZE)
        except unicorn.UcError:
            pass

def AddDirtyRange(state, start: int, end: int) -> None:
    if state is None:
        return
    if end <= start:
        return
    dirty_ranges = state.get('uc_dirty_ranges')
    if dirty_ranges is None:
        return
    dirty_ranges.append((start, end))
    if len(dirty_ranges) > 512:
        dirty_ranges.sort()
        merged = []
        for cur_start, cur_end in dirty_ranges:
            if not merged or cur_start > merged[-1][1]:
                merged.append([cur_start, cur_end])
            else:
                merged[-1][1] = max(merged[-1][1], cur_end)
        state['uc_dirty_ranges'] = [(cur_start, cur_end) for cur_start, cur_end in merged[-512:]]

def MarkRangeClean(state, start: int, end: int) -> None:
    if state is None:
        return
    dirty_ranges = state.get('uc_dirty_ranges')
    if dirty_ranges is None:
        return
    cleaned = []
    for dirty_start, dirty_end in dirty_ranges:
        if not IsRangeOverlap(start, end, dirty_start, dirty_end):
            cleaned.append((dirty_start, dirty_end))
            continue
        if dirty_start < start:
            cleaned.append((dirty_start, start))
        if end < dirty_end:
            cleaned.append((end, dirty_end))
    state['uc_dirty_ranges'] = cleaned

def GetOrCreateFiberState(state, handle: int) -> FiberTraceState:
    fibers: dict[int, FiberTraceState] = state['fibers']
    fiber = fibers.get(handle)
    if fiber is None:
        fiber = FiberTraceState(handle=handle)
        fibers[handle] = fiber
    return fiber

def RecordCurrentFiber(state, handle: int, resume_rip: int = 0) -> None:
    if not handle:
        return
    fiber = GetOrCreateFiberState(state, handle)
    if not fiber.call_stack and state.get('call_stack') is not fiber.call_stack:
        fiber.call_stack = state.get('call_stack', [])
    if resume_rip:
        fiber.resume_rip = resume_rip
    state['current_fiber'] = handle
    state['call_stack'] = fiber.call_stack
    print(f'[fiber-current] handle={hex(handle)} resume={hex(fiber.resume_rip)}')

def RecordCreatedFiber(state, handle: int, start_address: int, parameter: int) -> None:
    if not handle:
        return
    fiber = GetOrCreateFiberState(state, handle)
    fiber.start_address = start_address
    fiber.parameter = parameter
    AddTraceRangeForAddress(state['client'], state, start_address, f'fiber:{hex(handle)}')
    print(f'[fiber-create] handle={hex(handle)} start={hex(start_address)} param={hex(parameter)}')

def SaveCurrentFiberBeforeSwitch(state, return_to: int) -> None:
    current_handle = state.get('current_fiber', 0)
    if not current_handle:
        return
    fiber = GetOrCreateFiberState(state, current_handle)
    fiber.resume_rip = return_to
    fiber.call_stack = state['call_stack']
    print(f'[fiber-save] handle={hex(current_handle)} resume={hex(return_to)} depth={len(fiber.call_stack)}')

def CandidateFiberEntryAddrs(state, target_handle: int) -> list[int]:
    fiber = state['fibers'].get(target_handle)
    if fiber is None:
        return []
    candidates = []
    if fiber.entered and fiber.resume_rip:
        candidates.append(fiber.resume_rip)
    if fiber.start_address:
        candidates.append(fiber.start_address)
    if fiber.resume_rip:
        candidates.append(fiber.resume_rip)
    result = []
    seen = set()
    for addr in candidates:
        if addr and addr not in seen:
            seen.add(addr)
            result.append(addr)
    return result

def SetFiberEntryBreakpoints(client: x64dbg_automate.X64DbgClient, state, target_handle: int) -> list[int]:
    addrs = CandidateFiberEntryAddrs(state, target_handle)
    for addr in addrs:
        SetX64DbgBreakpoint(client, addr)
    print(f'[fiber-bp] target={hex(target_handle)} addrs={",".join(hex(addr) for addr in addrs) or "none"}')
    return addrs

def ApplyFiberSwitchState(state, target_handle: int, current_rip: int) -> None:
    fiber = GetOrCreateFiberState(state, target_handle)
    fiber.entered = True
    fiber.switch_count += 1
    AddTraceRangeForAddress(state['client'], state, current_rip, f'fiber-switch:{hex(target_handle)}')
    if not fiber.resume_rip or current_rip != fiber.start_address:
        fiber.resume_rip = current_rip
    state['current_fiber'] = target_handle
    state['call_stack'] = fiber.call_stack
    print(
        f'[fiber-switch] target={hex(target_handle)} rip={hex(current_rip)} start={hex(fiber.start_address)} depth={len(fiber.call_stack)}')

def HandleFiberReturnApis(state, snap: ApiSnapshot, current_regs: dict[str, int]) -> None:
    if IsConvertThreadToFiberApi(snap.label):
        RecordCurrentFiber(state, current_regs['rax'], snap.ret_addr)
    elif IsCreateFiberApi(snap.label):
        start_address = snap.regs['rdx'] if NormalizeApiName(snap.label).endswith('createfiber') else snap.regs['r9']
        parameter = snap.regs['r8'] if NormalizeApiName(snap.label).endswith('createfiber') else ReadX64DbgStackArg(
            state['client'], snap.rsp, 0)
        RecordCreatedFiber(state, current_regs['rax'], start_address, parameter)

def RunX64DbgThroughSwitchToFiber(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, state, user_start: int,
                                  user_end: int) -> bool:
    target_handle = snap.regs['rcx']
    SaveCurrentFiberBeforeSwitch(state, snap.ret_addr)
    bps = SetFiberEntryBreakpoints(client, state, target_handle)
    if not bps:
        print(f'[fiber-warning] unknown target fiber {hex(target_handle)}, falling back to next usercode stop')
        ok = RunX64DbgUntilUserCode(client, user_start, user_end)
    else:
        client.go(pass_exceptions=True)
        client.wait_until_stopped()
        rip = client.get_reg('rip')
        print(f'[fiber-stop] target={hex(target_handle)} rip={hex(rip)} label={GetSymbolLabel(client, rip)}')
        ok = rip in bps or IsInRange(rip, user_start, user_end)
    if not ok:
        return False
    current_rip = client.get_reg('rip')
    if not IsTraceAddress(state, current_rip):
        AddTraceRangeForAddress(client, state, current_rip, f'fiber-stop:{hex(target_handle)}')
    ApplyFiberSwitchState(state, target_handle, current_rip)
    return True

def PopCallByReturn(state, return_to: int) -> int:
    call_stack = state['call_stack']
    for i in range(len(call_stack) - 1, -1, -1):
        ret_addr, call_addr = call_stack[i]
        if ret_addr == return_to:
            del call_stack[i]
            return call_addr
    return 0

def IsBlockEnd(insn: capstone.CsInsn) -> bool:
    return insn.mnemonic.startswith('j') or insn.mnemonic == 'call' or insn.mnemonic == 'ret'

def FormatInsnLine(insn: capstone.CsInsn, tag: str = '[exec]') -> str:
    return f'{tag} 0x{insn.address:x}: {insn.mnemonic}\t{insn.op_str}'

def GetBlockInfo(uc: unicorn.Uc, state, start: int) -> dict[str, int]:
    block_cache = state['block_cache']
    if start in block_cache:
        return block_cache[start]

    cur = start
    while True:
        insn = ReadInsn(uc, cur)
        if IsBlockEnd(insn):
            info = {'start': start, 'end': insn.address, 'count': 0, 'id': state['block_next_id']}
            state['block_next_id'] += 1
            block_cache[start] = info
            return info
        cur += insn.size

def ShouldPrintInsn(uc: unicorn.Uc, state, address: int, insn: capstone.CsInsn) -> bool:
    if not USE_BLOCK_CACHE:
        return True

    if state['block_pending_start']:
        block = GetBlockInfo(uc, state, address)
        block['count'] += 1
        state['block_pending_start'] = False
        state['block_current_id'] = block['id']
        state['block_current_start'] = block['start']
        state['block_current_end'] = block['end']
        if block['count'] > 1:
            state['block_silent_end'] = block['end']
            print(f"[block] {hex(address)} id={block['id']}")
            return False
        state['block_silent_end'] = 0

    if state['block_silent_end']:
        if address == state['block_silent_end']:
            state['block_pending_start'] = True
            state['block_silent_end'] = 0
        return False
    return True

def DumpFaultBlock(uc: unicorn.Uc, state) -> None:
    if not USE_BLOCK_CACHE:
        return
    start = state.get('block_current_start')
    if not start:
        return
    fault_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
    block_id = state.get('block_current_id', 0)
    print(f'[fault-block] id={block_id} {hex(start)} -> {hex(fault_rip)}')

    cur = start
    visited = set()
    while cur not in visited:
        visited.add(cur)
        try:
            insn = ReadInsn(uc, cur)
        except unicorn.UcError as exc:
            print(f'[fault-block-read-fail] {hex(cur)}: {exc}')
            return
        tag = '[fault]' if cur == fault_rip else '[exec]'
        print(FormatInsnLine(insn, tag))
        if cur == fault_rip or IsBlockEnd(insn):
            return
        cur += insn.size

def MapInitialMemory(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, rip: int, rsp: int) -> None:
    code_page = FindMemPage(client, rip)
    stack_page = FindMemPage(client, rsp)
    if code_page is None:
        raise RuntimeError(f'RIP page not found: {hex(rip)}')
    if stack_page is None:
        raise RuntimeError(f'RSP page not found: {hex(rsp)}')

    code_alloc_base = code_page.allocation_base
    for page in client.memmap():
        if page.allocation_base == code_alloc_base or page == stack_page:
            if not MapPageFromX64Dbg(uc, client, page):
                raise RuntimeError(f'Initial map failed: {hex(page.base_address)}')

    MapTebMemory(uc, client, rsp)

    # Keep a little stack slack available for pushes/calls during short simulation.
    stack_start = utils_uc.AlignDown(max(0, rsp - STACK_EXTRA))
    stack_end = utils_uc.AlignUp(rsp + STACK_EXTRA)
    try:
        uc.mem_map(stack_start, stack_end - stack_start)
    except unicorn.UcError:
        pass

def UC_RegsWrite(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient) -> None:
    for name, reg in REGS64:
        uc.reg_write(reg, client.get_reg(name))
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RFLAGS, client.get_reg('rflags') & ~RFLAGS_TF)

def FormatUcRegs(uc: unicorn.Uc) -> str:
    return ' '.join(f'{name.upper()}={uc.reg_read(reg):x}' for name, reg in REGS64)

def ReadInsn(uc: unicorn.Uc, addr: int) -> capstone.CsInsn:
    return next(cs.disasm(uc.mem_read(addr, 16), addr, 1))

def DumpStopState(uc: unicorn.Uc) -> None:
    current_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
    try:
        insn = ReadInsn(uc, current_rip)
        print(f'[stop] 0x{current_rip:x}: {insn.mnemonic}\t{insn.op_str}')
    except unicorn.UcError:
        print(f'[stop] 0x{current_rip:x}')
    utils_uc.DumpRegs(uc, 64)
    utils_uc.DumpStack(uc, 8)

def CodeHook(uc: unicorn.Uc, address: int, size: int, user_data) -> None:
    state = user_data
    if address == state.get('trace_ret_rip', 0):
        state['leave_rip'] = address
        print(f'[leave-ret] 0x{address:x}')
        uc.emu_stop()
        return
    # if IsChkstk(address, state['user_start']):
    #     state['leave_rip'] = address
    #     print(f'[leave-runtime] __chkstk 0x{address:x}')
    #     uc.emu_stop()
    #     return
    if not IsTraceAddress(state, address):
        state['leave_rip'] = address
        print(f'[leave-usercode] 0x{address:x}')
        uc.emu_stop()
        return

    insn = ReadInsn(uc, address)
    should_print = LOG_EXEC and ShouldPrintInsn(uc, state, address, insn)
    if should_print:
        print(FormatInsnLine(insn))
    if insn.mnemonic == 'call':
        ret_addr = address + insn.size
        state['call_stack'].append((ret_addr, address))
        if should_print:
            target = GetCallTarget(insn)
            target_text = f' target=0x{target:x}' if target is not None else ''
            print(f'[call] call=0x{address:x} ret=0x{ret_addr:x}{target_text} regs={FormatUcRegs(uc)}')
        if USE_BLOCK_CACHE:
            state['block_pending_start'] = True
            state['block_silent_end'] = 0
    elif insn.mnemonic.startswith('j'):
        if should_print:
            print(f'[jcc] 0x{address:x}: {insn.mnemonic}\t{insn.op_str} regs={FormatUcRegs(uc)}')
        if USE_BLOCK_CACHE:
            state['block_pending_start'] = True
            state['block_silent_end'] = 0
    elif insn.mnemonic == 'ret':
        rax = uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX)
        call_addr = 0
        return_to = 0
        if state['call_stack']:
            return_to, call_addr = state['call_stack'].pop()
        if should_print:
            print(f'[ret] ret=0x{address:x} call=0x{call_addr:x} return_to=0x{return_to:x} rax=0x{rax:x}')
        if USE_BLOCK_CACHE:
            state['block_pending_start'] = True
            state['block_silent_end'] = 0

def MemReadHook(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state) -> None:
    if not SYNC_ON_MEM_READ:
        return
    if IsUcSyncing(state):
        return
    if not IsPotentialUserPtr(address):
        return
    if size <= 0:
        size = 1
    memsync = state.get('memsync')
    if memsync is None:
        return
    end = address + size
    cache_key = (kind := 'read', utils_uc.AlignDown(address), end - utils_uc.AlignDown(address))
    if cache_key in state['mem_read_sync_cache']:
        return
    if not memsync.before_access(address, size, 'read'):
        print(f'[sync-read-skip] addr={hex(address)} size={size}')
        return
    state['mem_read_sync_cache'].add(cache_key)

def MemWriteHook(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state) -> None:
    if IsUcSyncing(state):
        return
    if not IsPotentialUserPtr(address):
        return
    if size <= 0:
        size = 1
    AddDirtyRange(state, address, address + size)

def MemFetchHook(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state) -> None:
    if not SYNC_ON_MEM_READ:
        return
    if IsUcSyncing(state):
        return
    if not IsPotentialUserPtr(address):
        return
    if size <= 0:
        size = 1
    memsync = state.get('memsync')
    if memsync is not None:
        memsync.before_access(address, size, 'fetch')

def InvalidMemHook(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state) -> bool:
    print(f'[uc-invalid] access={access} addr={hex(address)} size={size}')
    if IsUcSyncing(state):
        return False
    if not IsPotentialUserPtr(address):
        return False
    if size <= 0:
        size = 1
    memsync = state.get('memsync')
    if memsync is not None:
        return memsync.map_page_for_invalid(address, access)
    return False

def SyncX64DbgToTraceRet(client: x64dbg_automate.X64DbgClient, uc: unicorn.Uc, state, trace_ret_rip: int,
                         expected_rsp: int) -> None:
    if not RunX64DbgUntilContext(client, trace_ret_rip, expected_rsp, 'trace-ret'):
        FatalExit(client, uc,
                  f'[x64dbg-warning] expected trace ret {hex(trace_ret_rip)} rsp={hex(expected_rsp)}, '
                  f'current rip={hex(client.get_reg("rip"))} rsp={hex(client.get_reg("rsp"))}', 1, state)

    current_regs = ReadApiRegs(client)
    memsync = state['memsync']
    memsync.reset_after_xdbg_run('trace-ret')
    MapTebMemory(uc, client, current_regs['rsp'])
    UC_RegsWrite(uc, client)
    print(f'[trace-ret-sync] rip={hex(client.get_reg("rip"))} rsp={hex(client.get_reg("rsp"))}')

def TraceUntilRet(client: x64dbg_automate.X64DbgClient) -> unicorn.Uc:
    rip = client.get_reg('rip')
    rsp = client.get_reg('rsp')
    print(f'[start] rip={hex(rip)} rsp={hex(rsp)}')

    user_start, user_end = GetUserCodeRange(client, rip)
    print(f'[usercode] {hex(user_start)}-{hex(user_end)}')
    EnsureStartInUserCode(client, user_start, user_end)

    rip = client.get_reg('rip')
    rsp = client.get_reg('rsp')
    print(f'[sync-start] rip={hex(rip)} rsp={hex(rsp)}')

    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    MapInitialMemory(uc, client, rip, rsp)
    UC_RegsWrite(uc, client)
    stack_start = utils_uc.AlignDown(max(0, rsp - STACK_EXTRA))
    stack_end = utils_uc.AlignUp(rsp + STACK_EXTRA)
    trace_ret_rip = utils_uc.ReadU64Le(uc, rsp)
    trace_ret_rsp = rsp + 8
    print(f'[trace-ret] rip={hex(trace_ret_rip)} rsp={hex(trace_ret_rsp)}')

    state = {
        'client': client,
        'user_start': user_start,
        'user_end': user_end,
        'trace_ranges': [(user_start, user_end)],
        'trace_ret_rip': trace_ret_rip,
        'stack_start': stack_start,
        'stack_end': stack_end,
        'leave_rip': 0,
        'call_stack': [],
        'fibers': {},
        'current_fiber': 0,
        'block_cache': {},
        'block_pending_start': True,
        'block_silent_end': 0,
        'block_next_id': 1,
        'block_current_id': 0,
        'block_current_start': 0,
        'block_current_end': 0,
        'mem_read_sync_cache': set(),
        'uc_dirty_ranges': [],
        'sync_depth': 0,
    }
    state['memsync'] = MemSyncManager(uc, client, state)
    uc.hook_add(unicorn.UC_HOOK_CODE, CodeHook, state)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ, MemReadHook, state)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, MemWriteHook, state)
    uc.hook_add(unicorn.UC_HOOK_MEM_FETCH, MemFetchHook, state)
    uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, InvalidMemHook, state)

    while True:
        state['leave_rip'] = 0
        state['mem_read_sync_cache'].clear()
        start_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        try:
            uc.emu_start(start_rip, -1)
        except unicorn.UcError as e:
            FatalExit(client, uc, str(e), 1, state)

        leave_rip = int(state['leave_rip'])
        if not leave_rip:
            break
        if leave_rip == trace_ret_rip:
            SyncX64DbgToTraceRet(client, uc, state, trace_ret_rip, trace_ret_rsp)
            break

        expected_ret = utils_uc.ReadU64Le(uc, uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP))
        if not RunX64DbgUntilApiCall(client, leave_rip, expected_ret):
            FatalExit(client, uc,
                      f'[x64dbg-warning] expected api {hex(leave_rip)}, current {hex(client.get_reg("rip"))}', 1, state)
        api_rsp = client.get_reg('rsp')
        snap = ApiSnapshot(
            rip=leave_rip,
            rsp=api_rsp,
            ret_addr=ReadX64DbgU64(client, api_rsp),
            label=GetSymbolLabel(client, leave_rip),
            regs=ReadApiRegs(client),
            args=ReadApiArgs(client, api_rsp, GetSymbolLabel(client, leave_rip)),
        )
        print(
            f'[api] {snap.label} at {hex(snap.rip)}, ret={hex(snap.ret_addr)}, args={ApiSyncLayer.format_args(client, snap)}')
        is_switch_fiber = IsSwitchToFiberApi(snap.label)
        if is_switch_fiber:
            print(f'[context-api] {snap.label} ret={hex(snap.ret_addr)}')
            if not RunX64DbgThroughSwitchToFiber(client, snap, state, user_start, user_end):
                FatalExit(client, uc,
                          f'[x64dbg-warning] expected fiber usercode after {snap.label}, current {hex(client.get_reg("rip"))}',
                          1, state)
        elif not RunX64DbgUntil(client, snap.ret_addr):
            FatalExit(client, uc,
                      f'[x64dbg-warning] expected ret {hex(snap.ret_addr)}, current {hex(client.get_reg("rip"))}', 1,
                      state)
        api_call_addr = 0 if is_switch_fiber else PopCallByReturn(state, expected_ret)
        current_regs = ReadApiRegs(client)
        if not is_switch_fiber:
            HandleFiberReturnApis(state, snap, current_regs)
        ret_value = current_regs['rax']
        result_text = ApiSyncLayer.format_result(client, snap, current_regs)
        suffix = f' {result_text}' if result_text else ''
        print(
            f'[ret] ret=0x{leave_rip:x} call=0x{api_call_addr:x} return_to=0x{expected_ret:x} rax=0x{ret_value:x}{suffix}')
        current_dbg_rip = current_regs['rip']
        if not IsTraceAddress(state, current_dbg_rip):
            FatalExit(client, uc, f'[stop] still outside usercode: {hex(current_dbg_rip)}', 1, state)

        memsync = state['memsync']
        memsync.reset_after_xdbg_run(f'api:{snap.label}')
        MapTebMemory(uc, client, current_regs['rsp'])
        UC_RegsWrite(uc, client)
        if is_switch_fiber:
            print(f'[context-sync] {snap.label} rip={hex(client.get_reg("rip"))} rsp={hex(client.get_reg("rsp"))}')
            if not client.is_debugging():
                print(f'[context-stop] debugger session ended after {snap.label}')
                break

        current_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        if not IsTraceAddress(state, current_rip):
            FatalExit(client, uc, f'[stop] still outside usercode: {hex(current_rip)}', 1, state)

    DumpStopState(uc)
    return uc

def main():
    with redirect_stdout_stderr_to_file(LOG_TO_FILE, LOG_FILE_PATH):
        try:
            client = GetClient()
            TraceUntilRet(client)
            print('[done] TraceUntilRet completed')
            if client is not None:
                ClearManagedBreakpoints(client)
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)
        except BaseException:
            traceback.print_exc(file=sys.stdout)
            if client is not None:
                try:
                    ClearManagedBreakpoints(client)
                except Exception:
                    traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(1)

if __name__ == '__main__':
    main()
