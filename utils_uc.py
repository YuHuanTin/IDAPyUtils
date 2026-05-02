from typing import Literal

import unicorn

def SwicthEndian(b):
    return b[::-1]

def ReadU16Le(uc: unicorn.Uc, addr: int):
    return int.from_bytes(uc.mem_read(addr, 2), 'little')

def ReadU32Le(uc: unicorn.Uc, addr: int):
    return int.from_bytes(uc.mem_read(addr, 4), 'little')

def ReadU64Le(uc: unicorn.Uc, addr: int):
    return int.from_bytes(uc.mem_read(addr, 8), 'little')

def AlignDown(addr):
    return addr & ~0xFFF

def AlignUp(addr):
    return (addr + 0xFFF) & ~0xFFF

def DumpStack(uc: unicorn.Uc, stackSize: Literal[4, 8], deep: int = 16) -> None:
    upNum = deep // 2
    downNum = deep - upNum

    if stackSize == 4:
        esp = uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        for i in range(upNum, 0, -1):
            print(f'{esp + i * 4:08x}: {ReadU32Le(uc, esp + i * 4):08x}')
        print(f'> {esp:08x}: {ReadU32Le(uc, esp):08x}')
        for i in range(1, downNum):
            print(f'{esp - i * 4:08x}: {ReadU32Le(uc, esp - i * 4):08x}')
    elif stackSize == 8:
        rsp = uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
        for i in range(upNum, 0, -1):
            print(f'{rsp + i * 8:016x}: {ReadU64Le(uc, rsp + i * 8):016x}')
        print(f'> {rsp:016x}: {ReadU64Le(uc, rsp):016x}')
        for i in range(1, downNum):
            print(f'{rsp - i * 8:016x}: {ReadU64Le(uc, rsp - i * 8):016x}')
    pass

def DumpRegs(uc: unicorn.Uc, mode: Literal[16, 32, 64]) -> None:
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
