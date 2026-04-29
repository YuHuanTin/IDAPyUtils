"""
这是 IDA 端视角下执行的代码
"""

"""
通用环境初始化：自动处理路径并清理本地模块缓存
必须最先调用
"""
import importlib

def init_env():
    # 1. 获取当前脚本所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # 2. 修正 sys.path 优先级
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    elif sys.path[0] != current_dir:
        sys.path.remove(current_dir)
        sys.path.insert(0, current_dir)

    # 3. 自动清理所有本地模块缓存 (核心逻辑)
    # 我们遍历已加载的模块，如果模块的文件路径在当前目录下，就把它从内存中删掉
    for module_name in list(sys.modules.keys()):
        module = sys.modules.get(module_name)
        if module and hasattr(module, '__file__') and module.__file__:
            # 如果模块路径是以当前目录开头的，说明是你自己写的业务代码
            if module.__file__.startswith(current_dir):
                del sys.modules[module_name]

init_env()
"""
通用环境初始化：自动处理路径并清理本地模块缓存
"""

from typing import Literal

from rich import inspect  # inspect(a[0], methods=True, private=True)
from utils import *
import unicorn
import capstone

# import keystone

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

def unicorn_code_hook(uc: Uc, address: int, size: int, user_data: int) -> None:
    user_data: list[SegmentInfo] = user_data

    def GetSegmentNameByAddr(addr: int) -> str:
        for seg in user_data:
            if seg.start <= addr < seg.start + seg.len:
                return seg.name
        return "unknown"

    def GetCodeTag(inst: CsInsn):
        if inst.mnemonic.startswith('j'):
            return '[jcc]   '
        return '        '

    d: CsInsn = list(cs.disasm(uc.mem_read(address, size), address))[0]

    print(f'{GetSegmentNameByAddr(address)}:0x{address:x}:{GetCodeTag(d)}{d.mnemonic}\t{d.op_str}')

    def DoCode(ea: int) -> None:
        if not IsCode(ea):
            print(f'{hex(ea)} is not code, be code')
            DelItem(ea)
            CreateInst(ea)
    
    # DoCode(address)

def runCode(ip: int, end: int, segmentsInfos: list[SegmentInfo]) -> None:
    def dumpStack(stackSize: Literal[4, 8], deep: int = 16) -> None:
        upNum = deep // 2
        downNum = deep - upNum

        if stackSize == 4:
            esp = uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
            for i in range(upNum, 0, -1):
                print(f'{esp + i * 4:08x}: {uc.mem_read(esp + i * 4, 4).hex()}')
            print(f'> {esp:08x}: {uc.mem_read(esp, 4).hex()}')
            for i in range(1, downNum):
                print(f'{esp - i * 4:08x}: {uc.mem_read(esp - i * 4, 4).hex()}')
        elif stackSize == 8:
            rsp = uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
            for i in range(upNum, 0, -1):
                print(f'{rsp + i * 8:016x}: {uc.mem_read(rsp + i * 8, 8).hex()}')
            print(f'> {rsp:016x}: {uc.mem_read(rsp, 8).hex()}')
            for i in range(1, downNum):
                print(f'{rsp - i * 8:016x}: {uc.mem_read(rsp - i * 8, 8).hex()}')
        pass

    def dumpRegs(mode: Literal[16, 32, 64]) -> None:
        if mode == 16:
            b = uc.reg_read_batch([
                unicorn.x86_const.UC_X86_REG_AX,
                unicorn.x86_const.UC_X86_REG_BX,
                unicorn.x86_const.UC_X86_REG_CX,
                unicorn.x86_const.UC_X86_REG_DX,
                unicorn.x86_const.UC_X86_REG_SI,
                unicorn.x86_const.UC_X86_REG_DI,
                unicorn.x86_const.UC_X86_REG_BP,
                unicorn.x86_const.UC_X86_REG_SP,
                unicorn.x86_const.UC_X86_REG_IP,
                unicorn.x86_const.UC_X86_REG_FLAGS,
            ])
            print(f'AX: {b[0]:x}\n'
                  f'BX: {b[1]:x}\n'
                  f'CX: {b[2]:x}\n'
                  f'DX: {b[3]:x}\n'
                  f'SI: {b[4]:x}\n'
                  f'DI: {b[5]:x}\n'
                  f'BP: {b[6]:x}\n'
                  f'SP: {b[7]:x}\n'
                  f'IP: {b[8]:x}\n'
                  f'FLAGS: {b[9]:x}')
        elif mode == 32:
            b = uc.reg_read_batch([
                unicorn.x86_const.UC_X86_REG_EAX,
                unicorn.x86_const.UC_X86_REG_EBX,
                unicorn.x86_const.UC_X86_REG_ECX,
                unicorn.x86_const.UC_X86_REG_EDX,
                unicorn.x86_const.UC_X86_REG_ESI,
                unicorn.x86_const.UC_X86_REG_EDI,
                unicorn.x86_const.UC_X86_REG_EBP,
                unicorn.x86_const.UC_X86_REG_ESP,
                unicorn.x86_const.UC_X86_REG_EIP,
                unicorn.x86_const.UC_X86_REG_EFLAGS,
            ])
            print(f'EAX: {b[0]:x}\n'
                  f'EBX: {b[1]:x}\n'
                  f'ECX: {b[2]:x}\n'
                  f'EDX: {b[3]:x}\n'
                  f'ESI: {b[4]:x}\n'
                  f'EDI: {b[5]:x}\n'
                  f'EBP: {b[6]:x}\n'
                  f'ESP: {b[7]:x}\n'
                  f'EIP: {b[8]:x}\n'
                  f'EFLAGS: {b[9]:x}')
        elif mode == 64:
            b = uc.reg_read_batch([
                unicorn.x86_const.UC_X86_REG_RAX,
                unicorn.x86_const.UC_X86_REG_RBX,
                unicorn.x86_const.UC_X86_REG_RCX,
                unicorn.x86_const.UC_X86_REG_RDX,
                unicorn.x86_const.UC_X86_REG_RSI,
                unicorn.x86_const.UC_X86_REG_RDI,
                unicorn.x86_const.UC_X86_REG_R8,
                unicorn.x86_const.UC_X86_REG_R9,
                unicorn.x86_const.UC_X86_REG_R10,
                unicorn.x86_const.UC_X86_REG_R11,
                unicorn.x86_const.UC_X86_REG_R12,
                unicorn.x86_const.UC_X86_REG_R13,
                unicorn.x86_const.UC_X86_REG_R14,
                unicorn.x86_const.UC_X86_REG_R15,
                unicorn.x86_const.UC_X86_REG_RBP,
                unicorn.x86_const.UC_X86_REG_RSP,
                unicorn.x86_const.UC_X86_REG_RIP,
                unicorn.x86_const.UC_X86_REG_RFLAGS,
            ])
            print(f'RAX: {b[0]:x}\n'
                  f'RBX: {b[1]:x}\n'
                  f'RCX: {b[2]:x}\n'
                  f'RDX: {b[3]:x}\n'
                  f'RSI: {b[4]:x}\n'
                  f'RDI: {b[5]:x}\n'
                  f'R8: {b[6]:x}\n'
                  f'R9: {b[7]:x}\n'
                  f'R10: {b[8]:x}\n'
                  f'R11: {b[9]:x}\n'
                  f'R12: {b[10]:x}\n'
                  f'R13: {b[11]:x}\n'
                  f'R14: {b[12]:x}\n'
                  f'R15: {b[13]:x}\n'
                  f'RBP: {b[14]:x}\n'
                  f'RSP: {b[15]:x}\n'
                  f'RIP: {b[16]:x}\n'
                  f'RFLAGS: {b[17]:x}')
        pass

    def align_down(addr):
        return addr & ~0xFFF

    def align_up(addr):
        return (addr + 0xFFF) & ~0xFFF

    # 1. 收集并计算所有段需要的页面范围
    page_ranges = []
    for seg in segmentsInfos:
        p_start = align_down(seg.start)
        p_end = align_up(seg.start + seg.len)
        page_ranges.append([p_start, p_end])

    # 2. 按起始地址排序
    page_ranges.sort(key=lambda x: x[0])

    # 3. 合并重叠的页面范围
    merged_blocks = []
    if page_ranges:
        current_start, current_end = page_ranges[0]
        for i in range(1, len(page_ranges)):
            next_start, next_end = page_ranges[i]
            if next_start < current_end:
                # 有重叠，合并范围
                current_end = max(current_end, next_end)
            else:
                # 无重叠，保存当前块，开始新块
                merged_blocks.append((current_start, current_end))
                current_start, current_end = next_start, next_end
        merged_blocks.append((current_start, current_end))

    # 4. 执行映射
    for b_start, b_end in merged_blocks:
        size = b_end - b_start
        print(f"[MAP] {hex(b_start)} - {hex(b_end)} (size: {hex(size)})")
        uc.mem_map(b_start, size)

    # 5. 写入原始数据（写入不需要对齐，只要地址已映射即可）
    for seg in segmentsInfos:
        raw_bytes = GetBytesFromEA(seg.start, seg.len)
        if raw_bytes:
            uc.mem_write(seg.start, raw_bytes)
            print(f"[WRITE] {len(raw_bytes)} bytes to {hex(seg.start)}")

    # 堆栈申请
    uc.mem_map(0x2000000, 0x0200000)  # 映射 2MB 的堆栈空间
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, 0x2200000 - 16 * 8)  # 预留 dump 堆栈，0x21FFF80

    # 添加代码 hook
    uc.hook_add(unicorn.UC_HOOK_CODE, unicorn_code_hook, segmentsInfos)

    try:
        uc.emu_start(ip, end)  # 执行代码
        dumpRegs(64)
    except unicorn.UcError as e:
        dumpRegs(64)
        dumpStack(8)

        print(e)

def main():
    start = '00007FF62A8947D4'

    runCode(int(start, 16), -1, GetSegments())

if __name__ == '__main__':
    main()
