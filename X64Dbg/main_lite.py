import contextlib
import os
import sys
import traceback
from dataclasses import dataclass

import capstone
import unicorn
import x64dbg_automate
from x64dbg_automate.models import MemPage

import utils_dbg
import utils_api
from Simulate import utils_uc

X64DBG_PATH = r"x64dbg.exe"
USER_CODE_INFO = 'calc.exe'

LOG_TO_FILE = True
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'run.log')
API_PARAMS_FILE = os.path.join(os.path.dirname(__file__), 'apis.txt')

LOG_MEM_LOG = False
LOG_MEM_ACCESS = False

CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CS.detail = True
UC = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

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

@dataclass
class State:
    client: x64dbg_automate.X64DbgClient
    memHookManager: MemSyncManager
    userCodeRange: tuple[int, int]

@contextlib.contextmanager
def redirect_stdout_stderr_to_file(enabled: bool, path: str):
    if not enabled:
        yield None
        return

    with open(path, 'w', encoding='utf-8', buffering=100 * 1024 * 1024) as f:
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            yield f
    pass

def UnmapMemory(uc: unicorn.Uc):
    for s, e, _ in uc.mem_regions():
        uc.mem_unmap(s, e - s + 1)

def MapTebMemory(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, sp: int):
    teb_page, tib = utils_dbg.GetCurrentTeb(client, sp)
    UC_SyncPage(uc, client, teb_page)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_GS_BASE, tib.teb_base)
    print(f'[uc-gs] base={hex(tib.teb_base)}')

def MapInitialMemory(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, rip: int, rsp: int):
    # 映射 code 与 stack
    code_page = utils_dbg.GetMemPageByAddr(client, rip)
    stack_page = utils_dbg.GetMemPageByAddr(client, rsp)

    for page in client.memmap():
        if page.allocation_base == code_page.allocation_base or page == stack_page:
            UC_SyncPage(uc, client, page)

    # 映射 TEB
    MapTebMemory(uc, client, rsp)

def UC_SyncPage(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient, page: MemPage):
    '''
    写入 dbg 内存页到 uc
    :param uc: 
    :param client: 
    :param page: 
    :return: 
    '''
    start = utils_uc.AlignDown(page.base_address)
    end = utils_uc.AlignUp(page.base_address + page.region_size)
    size = end - start

    data = client.read_memory(page.base_address, page.region_size)
    uc.mem_map(start, size)
    uc.mem_write(page.base_address, data)
    if LOG_MEM_LOG:
        print(f'[uc-map] {hex(page.base_address)}-{hex(page.base_address + page.region_size)} {page.info}')

def UC_SyncDbgRegs(uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient):
    '''
    写入 dbg 寄存器到 uc
    :param uc: 
    :param client: 
    :return: 
    '''
    for name, reg in REGS64:
        uc.reg_write(reg, client.get_reg(name))
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RFLAGS, client.get_reg('rflags') & ~RFLAGS_TF)

def ReadInsn(uc: unicorn.Uc, addr: int, size: int) -> capstone.CsInsn:
    return next(CS.disasm(uc.mem_read(addr, size), addr, 1))

def ucb_code(uc: unicorn.Uc, address: int, size: int, state: State):
    inst = ReadInsn(uc, address, size)
    print(inst)
    if not state.userCodeRange[0] <= address < state.userCodeRange[1]:
        uc.emu_stop()
        return
    pass

def ucb_mem_valid(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state: State):
    match access:
        case unicorn.UC_MEM_READ:
            if LOG_MEM_ACCESS:
                print(f'READ, addr: {address:x}, size: {size:x}, val: {utils_uc.ReadU64Le(uc, address):x}')
            pass
        case unicorn.UC_MEM_WRITE:
            if LOG_MEM_ACCESS:
                print(f'WRITE, addr: {address:x}, size: {size:x}, val: {value:x}')
            pass
        case unicorn.UC_MEM_FETCH:
            if LOG_MEM_ACCESS:
                print(f'FETCH, addr: {address:x}, size: {size:x}, val: {value:x}')
            pass
    pass

def ucb_mem_invalid(uc: unicorn.Uc, access: int, address: int, size: int, value: int, state: State) -> bool:
    match access:
        case unicorn.UC_MEM_READ_UNMAPPED:
            acc = 'READ_UNMAPPED'
        case unicorn.UC_MEM_WRITE_UNMAPPED:
            acc = 'WRITE_UNMAPPED'
        case unicorn.UC_MEM_FETCH_UNMAPPED:
            acc = 'FETCH_UNMAPPED'
    if LOG_MEM_ACCESS:
        print(f'{acc}, addr: {address:x}, size: {size:x}, val: {value:x}')
    state.memHookManager.SyncPageAndRead(address, size)
    return True

def GetSymbolLabelCommentOrOffset(client: x64dbg_automate.X64DbgClient, addr: int) -> str:
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
    page = utils_dbg.GetMemPageByAddr(client, addr)
    return f'{page.info}!{hex(addr)}'

def ReadRegs(client: x64dbg_automate.X64DbgClient) -> dict[str, int]:
    return {name: client.get_reg(name) for name, _ in REGS64}

class MemSyncManager:
    def __init__(self, uc: unicorn.Uc, client: x64dbg_automate.X64DbgClient):
        self.DEFAULT_PAGE_SIZE = 0x1000  # follow align
        self.page_cache: dict[int, bytes] = {}  # alignAddr -> data
        self.uc = uc
        self.client = client

    def ClearCache(self):
        self.page_cache.clear()

    def _is_mapped(self, page_base: int) -> bool:
        for beg, end, _ in self.uc.mem_regions():
            if beg <= page_base and page_base + self.DEFAULT_PAGE_SIZE - 1 <= end:
                return True
        return False

    def SyncPageAndRead(self, addr: int, size: int):
        if size > self.DEFAULT_PAGE_SIZE:
            raise RuntimeError('too large')

        # print('uc_map:', [(hex(b), hex(e)) for b, e, _ in list(UC.mem_regions())])
        # print('pc:', [hex(b) for b in list(self.page_cache.keys())])

        page_base = utils_uc.AlignDown(addr)
        offset = addr - page_base
        if page_base in self.page_cache:
            if self.page_cache[page_base][offset: offset + size] == self.client.read_memory(addr, size):
                return self.page_cache[page_base][offset: offset + size]
            else:
                # 缓存与真实环境不一致，重读页
                del self.page_cache[page_base]

        mem = self.client.read_memory(page_base, self.DEFAULT_PAGE_SIZE)

        if not self._is_mapped(page_base):
            self.uc.mem_map(page_base, self.DEFAULT_PAGE_SIZE)
        self.uc.mem_write(page_base, mem)
        self.page_cache[page_base] = mem
        return mem[offset: offset + size]

def TraceUntilRet(client: x64dbg_automate.X64DbgClient):
    rip = client.get_reg('rip')

    user_start, user_end = utils_dbg.GetUserCodeRange(client, USER_CODE_INFO)
    print(f'[usercode] {hex(user_start)}-{hex(user_end)}')
    if not user_start <= rip <= user_end:
        raise RuntimeError(f'CIP {hex(rip)} is outside of user code range {hex(user_start)}-{hex(user_end)}')

    # _, tib = utils_dbg.GetCurrentTeb(client, rsp)
    # stack_start = tib.stack_high
    # stack_end = tib.stack_low

    # todo, using deep control rather than rsp when cip not start of func
    # trace_ret_rip = utils_uc.ReadU64Le(UC, rsp)
    # trace_ret_rsp = rsp + 8
    # print(f'[trace-ret] rip={hex(trace_ret_rip)} rsp={hex(trace_ret_rsp)}')

    state = State(client, MemSyncManager(UC, client), (user_start, user_end))

    UC.hook_add(unicorn.UC_HOOK_CODE, ucb_code, state)
    # UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH
    # https://github.com/unicorn-engine/unicorn/blob/7c5db94191defc1e04a4f66f4eb1220903cba837/include/unicorn/unicorn.h#L429
    UC.hook_add(unicorn.UC_HOOK_MEM_VALID, ucb_mem_valid, state)
    # UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT
    UC.hook_add(unicorn.UC_HOOK_MEM_INVALID, ucb_mem_invalid, state)

    apiArgsCapturer = utils_api.APIArgsCapturer(API_PARAMS_FILE, client)
    while True:
        rip = client.get_reg('rip')
        rsp = client.get_reg('rsp')

        UnmapMemory(UC)
        MapInitialMemory(UC, client, rip, rsp)
        UC_SyncDbgRegs(UC, client)
        state.memHookManager.ClearCache()

        # 模拟，当 hook 返回 false 时正常退出
        UC.emu_start(UC.reg_read(unicorn.x86_const.UC_X86_REG_RIP), -1)

        # 获取模拟结束时 cip 与 返回地址
        rip = UC.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        callRet = utils_uc.ReadU64Le(UC, UC.reg_read(unicorn.x86_const.UC_X86_REG_RSP))

        # 获取 api 名称
        info = GetSymbolLabelCommentOrOffset(client, rip)
        print(f'[call] rip: {hex(rip)} info: {info}, callRet: {hex(callRet)}')

        # 注意 apiArgsCapturer 将会捕获 dbg 传参，所以要运行到 cip 位置
        utils_dbg.RunToAddress(client, rip)
        beforeApiCall = apiArgsCapturer.onEnter(info)
        print(f'before api call: {beforeApiCall}')

        # todo, 注意如果是 SwitchToFiber API，需要手动切换 CIP
        if beforeApiCall and beforeApiCall.name == 'SwitchToFiber':
            raise RuntimeError('SwitchToFiber not supported yet')

        utils_dbg.RunToAddress(client, callRet)
        afterApiCall = apiArgsCapturer.onLeave()
        print(f'after api call: {afterApiCall}')

def main():
    client = utils_dbg.GetClient(X64DBG_PATH)
    with redirect_stdout_stderr_to_file(LOG_TO_FILE, LOG_FILE_PATH):
        try:
            TraceUntilRet(client)
            print('[done] TraceUntilRet completed')
        except BaseException:
            traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        sys.stderr.flush()
    client.detach_session()

if __name__ == '__main__':
    main()
