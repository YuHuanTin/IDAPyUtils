from dataclasses import dataclass

import x64dbg_automate
from x64dbg_automate.models import BreakpointType

WINDOWS_MIN_PAGE_SIZE = 0x1000  # 4kb

@dataclass
class TIB:
    stack_high: int
    stack_low: int
    teb_base: int

def GetClient(xdbgPath: str) -> x64dbg_automate.X64DbgClient:
    client = x64dbg_automate.X64DbgClient(xdbgPath)
    if not client:
        raise RuntimeError('Failed to start x64dbg Automate client')

    sessions: list[DebugSession] = x64dbg_automate.X64DbgClient.list_sessions()
    if not sessions:
        raise RuntimeError('No x64dbg Automate session found')

    session = sessions[0]
    client.attach_session(session.pid)
    print(f'[x64dbg] attach session pid={session.pid}')
    return client

def GetUserCodeRange(client: x64dbg_automate.X64DbgClient, execName: str) -> tuple[int, int]:
    pages = client.memmap()
    bases = set()
    for page in pages:
        if execName.lower() in page.info.lower():
            bases.add(page.allocation_base)

    ranges = []
    for page in pages:
        if page.allocation_base in bases:
            ranges.append((page.base_address, page.base_address + page.region_size))

    return min(start for start, _ in ranges), max(end for _, end in ranges)

def GetMemPageByAddr(client: x64dbg_automate.X64DbgClient, addr: int) -> x64dbg_automate.models.MemPage:
    for page in client.memmap():
        if page.base_address <= addr < page.base_address + page.region_size:
            return page
    raise RuntimeError(f'Memory page not found for address {hex(addr)}')

def GetCurrentTeb(client: x64dbg_automate.X64DbgClient, sp: int) -> tuple[MemPage, TIB]:
    '''
    通过读取并解析所有标记为 `TEB` 的内存页，找到当前堆栈所属的 `TEB`
    :param client: 
    :param sp: 
    :return: 
    '''

    teb_pages = [page for page in client.memmap() if 'teb' in page.info.lower()]

    # 64
    '''
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void

//0x38 bytes (sizeof)
struct _NT_TIB
{
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                   //0x0
    VOID* StackBase;                                                        //0x8
    VOID* StackLimit;                                                       //0x10
    VOID* SubSystemTib;                                                     //0x18
    union
    {
        VOID* FiberData;                                                    //0x20
        ULONG Version;                                                      //0x20
    };
    VOID* ArbitraryUserPointer;                                             //0x28
    struct _NT_TIB* Self;                                                   //0x30
}; 
'''
    for page in teb_pages:
        for teb_base in range(page.base_address, page.base_address + page.region_size, WINDOWS_MIN_PAGE_SIZE):
            stack_base = client.read_qword(teb_base + 0x8)
            stack_limit = client.read_qword(teb_base + 0x10)
            self_ptr = client.read_qword(teb_base + 0x30)
            if self_ptr == teb_base and stack_limit <= sp <= stack_base:
                return page, TIB(stack_base, stack_limit, teb_base)

    # 32
    '''
ntdll!_TEB32
   +0x000 NtTib            : _NT_TIB32
   +0x01c EnvironmentPointer : Uint4B

//0x1c bytes (sizeof)
struct _NT_TIB32
{
    ULONG ExceptionList;                                                    //0x0
    ULONG StackBase;                                                        //0x4
    ULONG StackLimit;                                                       //0x8
    ULONG SubSystemTib;                                                     //0xc
    union
    {
        ULONG FiberData;                                                    //0x10
        ULONG Version;                                                      //0x10
    };
    ULONG ArbitraryUserPointer;                                             //0x14
    ULONG Self;                                                             //0x18
}; 
'''
    # todo, not tested yet
    for page in teb_pages:
        for teb_base in range(page.base_address, page.base_address + page.region_size, WINDOWS_MIN_PAGE_SIZE):
            stack_base = client.read_dword(teb_base + 0x4)
            stack_limit = client.read_dword(teb_base + 0x8)
            self_ptr = client.read_dword(teb_base + 0x18)
            if self_ptr == teb_base and stack_limit <= sp <= stack_base:
                return page, TIB(stack_base, stack_limit, teb_base)
    raise RuntimeError('TEB page not found')

# UI


# MEM 

def ReadMemUntilTermined(client: x64dbg_automate.X64DbgClient, addr: int, terminedBytes: bytes):
    data = bytearray()

    thunk_size = 256
    thunks = 0

    while True:
        c = client.read_memory(addr + thunks * thunk_size, thunk_size)
        terminator_index = c.find(terminedBytes)
        if terminator_index != -1:
            data.extend(c[:terminator_index])
            break
        else:
            data.extend(c)
            thunks += 1
    return data

def ReadAnsi(client: x64dbg_automate.X64DbgClient, addr: int) -> str:
    d = ReadMemUntilTermined(client, addr, b'\x00')
    return d.decode('mbcs', errors='ignore')

def ReadUtf16(client: x64dbg_automate.X64DbgClient, addr: int) -> str:
    d = ReadMemUntilTermined(client, addr, b'\x00\x00')
    return d.decode('utf-16le', errors='ignore')

# BP

def GetBreakpointsAt(client: x64dbg_automate.X64DbgClient, addr: int) -> list[x64dbg_automate.models.Breakpoint]:
    # all type
    return [bp for bp in client.get_breakpoints(BreakpointType.BpNone) if bp.addr == addr]

# Debugging

def RunToAddress(client: x64dbg_automate.X64DbgClient, addr: int):
    # set a bp in target addr
    bps = GetBreakpointsAt(client, addr)
    if len(bps) > 0:
        for bp in bps:
            if not bp.enabled:
                client.toggle_breakpoint(bp.addr)
    else:
        client.set_breakpoint(addr, singleshoot=True)

    client.go()
    client.wait_until_stopped()
    pass
