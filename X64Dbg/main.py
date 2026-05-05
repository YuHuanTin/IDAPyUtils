import contextlib
import os
import sys
import traceback
from dataclasses import dataclass

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

def IsChkstk(addr: int, user_start: int) -> bool:
    return addr == user_start + CHKSTK_OFFSET

def GetCallTarget(insn: capstone.CsInsn) -> int | None:
    if insn.mnemonic != 'call' or not insn.operands:
        return None
    op = insn.operands[0]
    return op.imm if op.type == capstone.x86_const.X86_OP_IMM else None

def HasX64DbgBreakpoint(client: x64dbg_automate.X64DbgClient, addr: int) -> bool:
    bp_types = (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory)
    breakpoints: list[Breakpoint] = []
    for bp_type in bp_types:
        breakpoints.extend(client.get_breakpoints(bp_type))
    return any(bp.addr == addr for bp in breakpoints)

def SetX64DbgBreakpoint(client: x64dbg_automate.X64DbgClient, addr: int) -> None:
    if HasX64DbgBreakpoint(client, addr):
        print(f'[x64dbg-bp-exists] {hex(addr)}')
        return
    client.set_breakpoint(addr, singleshoot=True)
    print(f'[x64dbg-bp] {hex(addr)}')

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

def FatalExit(client: x64dbg_automate.X64DbgClient | None, uc: unicorn.Uc | None, message: str, code: int = 1, state=None) -> None:
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
    rip = RunX64DbgToBreakpoint(client, addr)
    if rip == addr:
        return True
    print(f'[x64dbg-external-stop] expected {hex(addr)}, current {hex(rip)}')
    return False

def StepX64DbgOnce(client: x64dbg_automate.X64DbgClient) -> None:
    client.stepi(pass_exceptions=True)
    client.wait_until_stopped()

def RunX64DbgUntilApiCall(client: x64dbg_automate.X64DbgClient, api_addr: int, expected_ret: int, max_hits: int = 32) -> bool:
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

def ReadX64DbgStackArg(client: x64dbg_automate.X64DbgClient, api_rsp: int, index: int) -> int:
    return ReadX64DbgU64(client, api_rsp + 0x28 + index * 8)

def ReadApiRegs(client: x64dbg_automate.X64DbgClient) -> dict[str, int]:
    return {name: client.get_reg(name) for name, _ in REGS64}

def IsContextSwitchApi(api_label: str) -> bool:
    name = api_label.lower()
    return 'switchtofiber' in name or 'switchtothread' in name

@dataclass(slots=True)
class ApiSnapshot:
    rip: int
    rsp: int
    ret_addr: int
    label: str
    regs: dict[str, int]

@dataclass(slots=True)
class ApiParamSpec:
    name: str
    types: list[str]
    meta: list[dict[str, str]]

API_ARG_BASE_TYPES = {'cstr', 'wstr', 'u32ptr', 'u64ptr', 'u32', 'u64'}

def NormalizeApiName(name: str) -> str:
    name = name.split('!')[-1].split('.')[-1].strip()
    if name.startswith('<') and name.endswith('>'):
        name = name[1:-1]
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
            parts = [part.strip() for part in rest.replace('，', ',').split(',') if part.strip()]
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
            parsed = [ParseApiArgSpec(typ) for typ in raw_types[:count]]
            types = [typ for typ, _ in parsed]
            meta = [arg_meta for _, arg_meta in parsed]
            bad_type = next((typ for typ in types if ApiSyncLayerBaseType(typ) not in API_ARG_BASE_TYPES), None)
            if bad_type is not None:
                print(f'[api-spec-skip] line={line_no} bad type={bad_type}')
                continue
            specs[NormalizeApiName(name)] = ApiParamSpec(name.strip(), types, meta)
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
    def collect_sync_ranges(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, _current_regs: dict[str, int]) -> list[tuple[int, int]]:
        return ApiSyncLayer._typed_out_ranges(client, snap)

    @staticmethod
    def format_args(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot) -> str:
        spec = ApiSyncLayer._find_param_spec(snap.label)
        if spec is None:
            return ApiSyncLayer._format_raw_args(client, snap, 8)

        parts = []
        for index, arg_type in enumerate(spec.types):
            value = ApiSyncLayer._read_arg(client, snap, index)
            arg_name = ApiSyncLayer._arg_name(index)
            parts.append(f'{arg_name}:{arg_type}={hex(value)}{ApiSyncLayer._decode_typed_value(client, arg_type, value)}')
        return ', '.join(parts)

    @staticmethod
    def _format_raw_args(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, count: int) -> str:
        return ', '.join(f'{ApiSyncLayer._arg_name(i)}={hex(ApiSyncLayer._read_arg(client, snap, i))}' for i in range(count))

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
    def _read_arg(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, index: int) -> int:
        if index < 4:
            return snap.regs[ApiSyncLayer._arg_name(index)]
        return ReadX64DbgStackArg(client, snap.rsp, index - 4)

    @staticmethod
    def _typed_out_ranges(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot) -> list[tuple[int, int]]:
        spec = ApiSyncLayer._find_param_spec(snap.label)
        if spec is None:
            return []
        ranges = []
        for index, arg_type in enumerate(spec.types):
            if not arg_type.lower().endswith('_out'):
                continue
            value = ApiSyncLayer._read_arg(client, snap, index)
            if not IsPotentialUserPtr(value):
                continue
            size = ApiSyncLayer._infer_out_size(client, snap, spec, index)
            ranges.append((value, value + size))
        return ranges

    @staticmethod
    def _infer_out_size(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, spec: ApiParamSpec, index: int) -> int:
        arg_type = ApiSyncLayerBaseType(spec.types[index])
        natural_size = 8 if arg_type == 'u64ptr' else 4 if arg_type == 'u32ptr' else PAGE_SIZE
        meta = spec.meta[index]
        size = ApiSyncLayer._read_fixed_size(meta)
        if size is None:
            size = ApiSyncLayer._read_size_from_meta(client, snap, spec, meta)
        return max(natural_size, size) if size else natural_size

    @staticmethod
    def _read_fixed_size(meta: dict[str, str]) -> int | None:
        text = meta.get('size')
        return ApiSyncLayer._parse_int(text) if text else None

    @staticmethod
    def _read_size_from_meta(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, spec: ApiParamSpec, meta: dict[str, str]) -> int | None:
        size_from = meta.get('size_from')
        if not size_from:
            return None
        size_index = ApiSyncLayer._parse_arg_ref(size_from)
        if size_index is None or not 0 <= size_index < len(spec.types):
            return None
        size = ApiSyncLayer._read_size_arg(client, snap, spec, size_index, meta.get('size_type'))
        if size is None:
            return None
        scale = ApiSyncLayer._parse_int(meta.get('scale'), 1)
        return size * scale

    @staticmethod
    def _read_size_arg(client: x64dbg_automate.X64DbgClient, snap: ApiSnapshot, spec: ApiParamSpec, index: int, size_type: str | None) -> int | None:
        value = ApiSyncLayer._read_arg(client, snap, index)
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
    def _decode_typed_value(client: x64dbg_automate.X64DbgClient, arg_type: str, value: int) -> str:
        if not value:
            return ''
        typ = ApiSyncLayerBaseType(arg_type)
        if typ == 'cstr':
            text = ReadX64DbgAnsi(client, value) if IsReadableX64DbgPtr(client, value) else ''
            return f' "{text}"' if text else ''
        if typ == 'wstr':
            text = ReadX64DbgUtf16(client, value) if IsReadableX64DbgPtr(client, value) else ''
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

def MapPageAddrFromX64Dbg(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, addr: int) -> bool:
    if not IsPotentialUserPtr(addr):
        return False

    start = utils_uc.AlignDown(addr)
    page = FindMemPage(client, addr)
    read_start = start
    read_size = PAGE_SIZE
    page_info = 'direct'
    if page is not None:
        page_info = page.info
        read_start = max(start, page.base_address)
        read_size = min(PAGE_SIZE, page.base_address + page.region_size - read_start)
    if read_size <= 0:
        return False

    try:
        data = client.read_memory(read_start, read_size)
    except Exception as exc:
        print(f'[uc-map-fail] {hex(read_start)}-{hex(read_start + read_size)} {page_info}: {exc}')
        return False
    try:
        uc.mem_map(start, PAGE_SIZE)
    except unicorn.UcError:
        pass
    uc.mem_write(read_start, data)
    if LOG_UC_MAP:
        print(f'[uc-map-page] {hex(read_start)}-{hex(read_start + len(data))} {page_info}')
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

def SyncX64DbgMemoryGraph(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, ranges: list[tuple[int, int]]) -> None:
    seen_pages = set()
    for start, end in ranges:
        cur = utils_uc.AlignDown(start)
        end = utils_uc.AlignUp(end)
        while cur < end:
            if cur not in seen_pages:
                seen_pages.add(cur)
                if not MapPageAddrFromX64Dbg(uc, client, cur):
                    print(f'[sync-skip] cannot map {hex(cur)}')
            cur += PAGE_SIZE

    if LOG_UC_MAP:
        print(f'[sync-pages] {len(seen_pages)}')

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

def NormalizeFlags(flags: int) -> int:
    return flags & ~RFLAGS_TF

def WriteRegs(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient) -> None:
    for name, reg in REGS64:
        uc.reg_write(reg, client.get_reg(name))
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RFLAGS, NormalizeFlags(client.get_reg('rflags')))

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
    if IsChkstk(address, state['user_start']):
        state['leave_rip'] = address
        print(f'[leave-runtime] __chkstk 0x{address:x}')
        uc.emu_stop()
        return
    if not IsInRange(address, state['user_start'], state['user_end']):
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

def InvalidMemHook(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state) -> bool:
    print(f'[uc-invalid] access={access} addr={hex(address)} size={size}')
    return MapPageAddrFromX64Dbg(uc, state['client'], address)

def SimulateCurrentBlock(client: x64dbg_automate.X64DbgClient | None = None) -> unicorn.Uc:
    if client is None:
        client = GetClient()

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
    WriteRegs(uc, client)

    state = {
        'client': client,
        'user_start': user_start,
        'user_end': user_end,
        'leave_rip': 0,
        'call_stack': [],
        'block_cache': {},
        'block_pending_start': True,
        'block_silent_end': 0,
        'block_next_id': 1,
        'block_current_id': 0,
        'block_current_start': 0,
        'block_current_end': 0,
    }
    uc.hook_add(unicorn.UC_HOOK_CODE, CodeHook, state)
    uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, InvalidMemHook, state)

    while True:
        state['leave_rip'] = 0
        start_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        try:
            uc.emu_start(start_rip, -1)
        except unicorn.UcError as e:
            FatalExit(client, uc, str(e), 1, state)

        leave_rip = int(state['leave_rip'])
        if not leave_rip:
            break

        expected_ret = utils_uc.ReadU64Le(uc, uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP))
        if not RunX64DbgUntilApiCall(client, leave_rip, expected_ret):
            FatalExit(client, uc, f'[x64dbg-warning] expected api {hex(leave_rip)}, current {hex(client.get_reg("rip"))}', 1, state)
        api_rsp = client.get_reg('rsp')
        snap = ApiSnapshot(
            rip=leave_rip,
            rsp=api_rsp,
            ret_addr=ReadX64DbgU64(client, api_rsp),
            label=GetSymbolLabel(client, leave_rip),
            regs=ReadApiRegs(client),
        )
        print(f'[api] {snap.label} at {hex(snap.rip)}, ret={hex(snap.ret_addr)}, args={ApiSyncLayer.format_args(client, snap)}')
        if not RunX64DbgUntil(client, snap.ret_addr):
            FatalExit(client, uc, f'[x64dbg-warning] expected ret {hex(snap.ret_addr)}, current {hex(client.get_reg("rip"))}', 1, state)
        api_call_addr = PopCallByReturn(state, expected_ret)
        current_regs = ReadApiRegs(client)
        ret_value = current_regs['rax']
        print(f'[ret] ret=0x{leave_rip:x} call=0x{api_call_addr:x} return_to=0x{expected_ret:x} rax=0x{ret_value:x}')
        current_dbg_rip = current_regs['rip']
        if not IsInRange(current_dbg_rip, user_start, user_end):
            FatalExit(client, uc, f'[stop] still outside usercode: {hex(current_dbg_rip)}', 1, state)

        sync_ranges = ApiSyncLayer.collect_sync_ranges(client, snap, current_regs)
        SyncX64DbgMemoryGraph(uc, client, sync_ranges)
        MapTebMemory(uc, client, current_regs['rsp'])
        WriteRegs(uc, client)
        if IsContextSwitchApi(snap.label):
            state['call_stack'].clear()
            print(f'[context-sync] {snap.label} rip={hex(client.get_reg("rip"))} rsp={hex(client.get_reg("rsp"))}')

        current_rip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        if not IsInRange(current_rip, user_start, user_end):
            FatalExit(client, uc, f'[stop] still outside usercode: {hex(current_rip)}', 1, state)

    DumpStopState(uc)
    return uc

def main() -> None:
    with redirect_stdout_stderr_to_file(LOG_TO_FILE, LOG_FILE_PATH):
        try:
            SimulateCurrentBlock()
        except BaseException:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(1)

if __name__ == '__main__':
    main()
