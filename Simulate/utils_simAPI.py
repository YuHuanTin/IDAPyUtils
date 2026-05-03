from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import struct
import time
from typing import Any

import unicorn

import utils_uc


PAGE_SIZE = 0x1000
FILETIME_EPOCH = 116444736000000000
WAIT_OBJECT_0 = 0
INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF
STILL_ACTIVE = 259
DRIVE_FIXED = 3
TIME_ZONE_ID_UNKNOWN = 0
HEAP_HANDLE = 0x10000001
MAIN_MODULE = 0x140000000
PSEUDO_CURRENT_PROCESS = 0xFFFFFFFFFFFFFFFF
PSEUDO_CURRENT_THREAD = 0xFFFFFFFFFFFFFFFE

KNOWN_IMPORTS = {
    "CloseHandle",
    "ConvertThreadToFiber",
    "CreateDirectoryW",
    "CreateEventA",
    "CreateFileA",
    "CreateFileMappingA",
    "CreateFileW",
    "CreateMutexA",
    "CreateProcessW",
    "CreateSemaphoreA",
    "CreateThread",
    "DefineDosDeviceA",
    "DeleteFiber",
    "DeleteFileW",
    "DeviceIoControl",
    "DuplicateHandle",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FlushFileBuffers",
    "FreeLibrary",
    "GetComputerNameExW",
    "GetComputerNameW",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "GetDriveTypeA",
    "GetEnvironmentVariableA",
    "GetEnvironmentVariableW",
    "GetExitCodeThread",
    "GetFileInformationByHandle",
    "GetFileSize",
    "GetLastError",
    "GetLocalTime",
    "GetLogicalDrives",
    "GetModuleFileNameA",
    "GetModuleFileNameW",
    "GetModuleHandleA",
    "GetProcAddress",
    "GetProcessHeap",
    "GetProcessTimes",
    "GetSystemDirectoryA",
    "GetSystemInfo",
    "GetSystemTime",
    "GetSystemTimeAsFileTime",
    "GetTickCount",
    "GetTimeZoneInformation",
    "GetVersion",
    "GetVersionExA",
    "GetVolumeInformationA",
    "HeapFree",
    "LoadLibraryExA",
    "LocalAlloc",
    "LocalFree",
    "MapViewOfFile",
    "MoveFileExW",
    "MultiByteToWideChar",
    "OpenMutexA",
    "OpenProcess",
    "OpenSemaphoreA",
    "OutputDebugStringA",
    "QueryDosDeviceA",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "ReadFile",
    "ReleaseMutex",
    "ReleaseSemaphore",
    "RemoveDirectoryW",
    "ResumeThread",
    "RtlAllocateHeap",
    "RtlDeleteCriticalSection",
    "RtlEnterCriticalSection",
    "RtlInitializeCriticalSection",
    "RtlLeaveCriticalSection",
    "RtlReAllocateHeap",
    "RtlUnwindEx",
    "SearchPathA",
    "SetEndOfFile",
    "SetErrorMode",
    "SetEvent",
    "SetFileAttributesW",
    "SetFilePointerEx",
    "SetLastError",
    "SetThreadPriority",
    "Sleep",
    "SwitchToFiber",
    "SwitchToThread",
    "SystemTimeToFileTime",
    "TerminateProcess",
    "TerminateThread",
    "TlsAlloc",
    "TlsGetValue",
    "TlsSetValue",
    "UnmapViewOfFile",
    "WaitForSingleObject",
    "WideCharToMultiByte",
    "WriteFile",
    "__chkstk",
}


@dataclass
class HandleInfo:
    kind: str
    value: int = 0
    meta: dict[str, Any] = field(default_factory=dict)


class SimApi:
    def __init__(self, uc: unicorn.Uc):
        self.uc = uc
        self.last_error = 0
        self.next_heap = 0x0000020000000000
        self.next_handle = 0x4000
        self.next_tls = 1
        self.next_proc_stub = 0x0000030000000000
        self.allocations: dict[int, int] = {}
        self.handles: dict[int, HandleInfo] = {}
        self.tls_values: dict[int, int] = {}
        self.mapped_pages: set[int] = set()
        self.module_handles: dict[str, int] = {"": MAIN_MODULE}
        self.find_handles: dict[int, bool] = {}

    def dispatch(self, api_name: str) -> bool:
        handler = getattr(self, f"api_{api_name}", None)
        if handler is not None:
            handler()
            return True

        if api_name in {"CloseHandle", "CreateDirectoryW", "DefineDosDeviceA", "DeleteFileW", "FlushFileBuffers",
                        "FreeLibrary", "MoveFileExW", "OutputDebugStringA", "ReleaseMutex", "RemoveDirectoryW",
                        "ResumeThread", "RtlDeleteCriticalSection", "RtlEnterCriticalSection",
                        "RtlInitializeCriticalSection", "RtlLeaveCriticalSection", "SetEndOfFile", "SetEvent",
                        "SetFileAttributesW", "SetThreadPriority", "TerminateProcess", "TerminateThread",
                        "UnmapViewOfFile"}:
            self._ret(1)
            return True

        if api_name in {"DeleteFiber", "Sleep", "SwitchToFiber", "SwitchToThread"}:
            self._ret(0)
            return True

        if api_name in {"CreateEventA", "CreateMutexA", "CreateSemaphoreA", "OpenMutexA", "OpenProcess", "OpenSemaphoreA"}:
            self._ret(self._new_handle(api_name.lower()))
            return True

        if api_name in KNOWN_IMPORTS:
            print(f"[simAPI] fallback {api_name} -> 0")
            self._ret(0)
            return True

        return False

    def _reg(self, reg_id: int) -> int:
        return self.uc.reg_read(reg_id) & 0xFFFFFFFFFFFFFFFF

    def _rsp(self) -> int:
        return self._reg(unicorn.x86_const.UC_X86_REG_RSP)

    def _stack_arg(self, index: int) -> int:
        return utils_uc.ReadU64Le(self.uc, self._rsp() + 0x28 + index * 8)

    def _ret(self, value: int = 0) -> None:
        rsp = self._rsp()
        ret_addr = utils_uc.ReadU64Le(self.uc, rsp)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RIP, ret_addr)

    def _set_last_error(self, value: int) -> None:
        self.last_error = value & 0xFFFFFFFF

    def _ensure_mapped(self, addr: int, size: int) -> None:
        start = utils_uc.AlignDown(addr)
        end = utils_uc.AlignUp(addr + max(size, 1))
        page = start
        while page < end:
            if page not in self.mapped_pages:
                try:
                    self.uc.mem_read(page, 1)
                except unicorn.UcError:
                    self.uc.mem_map(page, PAGE_SIZE)
                self.mapped_pages.add(page)
            page += PAGE_SIZE

    def _alloc(self, size: int, zero: bool = True) -> int:
        alloc_size = max(size, 1)
        addr = utils_uc.AlignUp(self.next_heap)
        self._ensure_mapped(addr, alloc_size)
        if zero:
            self.uc.mem_write(addr, b"\x00" * alloc_size)
        self.allocations[addr] = alloc_size
        self.next_heap = utils_uc.AlignUp(addr + alloc_size + 0x20)
        return addr

    def _new_handle(self, kind: str, value: int = 0, **meta: Any) -> int:
        handle = self.next_handle
        self.next_handle += 4
        self.handles[handle] = HandleInfo(kind=kind, value=value, meta=meta)
        return handle

    def _read_c_string(self, addr: int) -> str:
        if not addr:
            return ""
        data = bytearray()
        for offset in range(0, 0x1000):
            ch = self.uc.mem_read(addr + offset, 1)
            if ch == b"\x00":
                break
            data += ch
        return data.decode("mbcs", errors="ignore")

    def _read_w_string(self, addr: int) -> str:
        if not addr:
            return ""
        data = bytearray()
        for offset in range(0, 0x2000, 2):
            ch = self.uc.mem_read(addr + offset, 2)
            if ch == b"\x00\x00":
                break
            data += ch
        return data.decode("utf-16le", errors="ignore")

    def _write_bytes(self, addr: int, data: bytes) -> None:
        if not addr:
            return
        self._ensure_mapped(addr, len(data))
        self.uc.mem_write(addr, data)

    def _write_u16(self, addr: int, value: int) -> None:
        self._write_bytes(addr, struct.pack("<H", value & 0xFFFF))

    def _write_u32(self, addr: int, value: int) -> None:
        self._write_bytes(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def _write_u64(self, addr: int, value: int) -> None:
        self._write_bytes(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def _write_c_string(self, addr: int, text: str, capacity: int) -> int:
        encoded = text.encode("mbcs", errors="ignore") + b"\x00"
        if capacity <= 0:
            return len(encoded)
        data = encoded[:capacity]
        if data[-1:] != b"\x00":
            data = data[:-1] + b"\x00"
        self._write_bytes(addr, data)
        return len(encoded)

    def _write_w_string(self, addr: int, text: str, capacity: int) -> int:
        encoded = text.encode("utf-16le", errors="ignore") + b"\x00\x00"
        if capacity <= 0:
            return len(encoded) // 2
        data = encoded[:capacity * 2]
        if data[-2:] != b"\x00\x00":
            data = data[:-2] + b"\x00\x00"
        self._write_bytes(addr, data)
        return len(encoded) // 2

    def _now_filetime(self) -> int:
        return FILETIME_EPOCH + int(time.time() * 10_000_000)

    def _write_filetime(self, addr: int, value: int | None = None) -> None:
        self._write_u64(addr, self._now_filetime() if value is None else value)

    def _write_system_time(self, addr: int, dt: datetime) -> None:
        fields = (
            dt.year,
            dt.month,
            dt.isoweekday() % 7,
            dt.day,
            dt.hour,
            dt.minute,
            dt.second,
            dt.microsecond // 1000,
        )
        self._write_bytes(addr, struct.pack("<8H", *fields))

    def _make_proc_stub(self, retval: int = 0) -> int:
        addr = utils_uc.AlignUp(self.next_proc_stub)
        self._ensure_mapped(addr, 0x100)
        if retval == 0:
            code = b"\x48\x31\xC0\xC3"
        else:
            code = b"\x48\xB8" + struct.pack("<Q", retval & 0xFFFFFFFFFFFFFFFF) + b"\xC3"
        self.uc.mem_write(addr, code)
        self.next_proc_stub = addr + 0x100
        return addr

    def api___chkstk(self) -> None:
        self._ret(0)

    def api_GetLastError(self) -> None:
        self._ret(self.last_error)

    def api_SetLastError(self) -> None:
        self._set_last_error(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        self._ret(0)

    def api_GetCurrentProcess(self) -> None:
        self._ret(PSEUDO_CURRENT_PROCESS)

    def api_GetCurrentProcessId(self) -> None:
        self._ret(0x1337)

    def api_GetCurrentThreadId(self) -> None:
        self._ret(0x4242)

    def api_GetProcessHeap(self) -> None:
        self._ret(HEAP_HANDLE)

    def api_RtlAllocateHeap(self) -> None:
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        self._ret(self._alloc(size))

    def api_RtlReAllocateHeap(self) -> None:
        old_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        new_size = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        new_ptr = self._alloc(new_size)
        old_size = self.allocations.get(old_ptr, 0)
        if old_ptr and old_size:
            copy_size = min(old_size, max(new_size, 1))
            self.uc.mem_write(new_ptr, bytes(self.uc.mem_read(old_ptr, copy_size)))
        self._ret(new_ptr)

    def api_HeapFree(self) -> None:
        self._ret(1)

    def api_LocalAlloc(self) -> None:
        size = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        self._ret(self._alloc(size))

    def api_LocalFree(self) -> None:
        self._ret(0)

    def api_TlsAlloc(self) -> None:
        slot = self.next_tls
        self.next_tls += 1
        self.tls_values[slot] = 0
        self._ret(slot)

    def api_TlsGetValue(self) -> None:
        slot = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        self._ret(self.tls_values.get(slot, 0))

    def api_TlsSetValue(self) -> None:
        slot = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        value = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        self.tls_values[slot] = value
        self._ret(1)

    def api_QueryPerformanceCounter(self) -> None:
        ptr = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        if ptr:
            self._write_u64(ptr, int(time.perf_counter() * 10_000_000))
        self._ret(1)

    def api_QueryPerformanceFrequency(self) -> None:
        ptr = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        if ptr:
            self._write_u64(ptr, 10_000_000)
        self._ret(1)

    def api_GetTickCount(self) -> None:
        self._ret(int(time.monotonic() * 1000) & 0xFFFFFFFF)

    def api_Sleep(self) -> None:
        self._ret(0)

    def api_WaitForSingleObject(self) -> None:
        self._ret(WAIT_OBJECT_0)

    def api_CreateThread(self) -> None:
        thread_id_ptr = self._stack_arg(2)
        handle = self._new_handle("thread", thread_id=0x4242)
        if thread_id_ptr:
            self._write_u32(thread_id_ptr, 0x4242)
        self._ret(handle)

    def api_GetExitCodeThread(self) -> None:
        ptr = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        if ptr:
            self._write_u32(ptr, STILL_ACTIVE)
        self._ret(1)

    def api_CreateEventA(self) -> None:
        self._ret(self._new_handle("event"))

    def api_CreateMutexA(self) -> None:
        self._ret(self._new_handle("mutex"))

    def api_CreateSemaphoreA(self) -> None:
        self._ret(self._new_handle("semaphore", count=self._reg(unicorn.x86_const.UC_X86_REG_RDX)))

    def api_OpenMutexA(self) -> None:
        self._ret(self._new_handle("mutex"))

    def api_OpenSemaphoreA(self) -> None:
        self._ret(self._new_handle("semaphore"))

    def api_OpenProcess(self) -> None:
        self._ret(self._new_handle("process"))

    def api_CloseHandle(self) -> None:
        handle = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        self.handles.pop(handle, None)
        self._ret(1)

    def api_ReleaseSemaphore(self) -> None:
        prev_count_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        if prev_count_ptr:
            self._write_u32(prev_count_ptr, 0)
        self._ret(1)

    def api_ReleaseMutex(self) -> None:
        self._ret(1)

    def api_GetModuleHandleA(self) -> None:
        name = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX)).lower()
        self._ret(self.module_handles.get(name, MAIN_MODULE if not name else 0))

    def api_LoadLibraryExA(self) -> None:
        name = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX)).lower()
        handle = self.module_handles.get(name)
        if handle is None:
            handle = self._new_handle("module")
            self.module_handles[name] = handle
        self._ret(handle)

    def api_GetProcAddress(self) -> None:
        proc_name = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RDX))
        retval = 1 if proc_name else 0
        self._ret(self._make_proc_stub(retval))

    def api_GetModuleFileNameA(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        path = r"C:\\Sandbox\\sample.exe"
        self._write_c_string(buf, path, size)
        self._ret(len(path))

    def api_GetModuleFileNameW(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        path = r"C:\\Sandbox\\sample.exe"
        self._write_w_string(buf, path, size)
        self._ret(len(path))

    def api_GetSystemDirectoryA(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        path = r"C:\\Windows\\System32"
        self._write_c_string(buf, path, size)
        self._ret(len(path))

    def api_GetEnvironmentVariableA(self) -> None:
        name = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        value = os.environ.get(name, "")
        required = self._write_c_string(buf, value, size)
        self._ret(0 if not value else required - 1)

    def api_GetEnvironmentVariableW(self) -> None:
        name = self._read_w_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        value = os.environ.get(name, "")
        required = self._write_w_string(buf, value, size)
        self._ret(0 if not value else required - 1)

    def api_GetComputerNameW(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        size_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        name = "SANDBOX"
        if size_ptr:
            capacity = utils_uc.ReadU32Le(self.uc, size_ptr)
            self._write_w_string(buf, name, capacity)
            self._write_u32(size_ptr, len(name))
        self._ret(1)

    def api_GetComputerNameExW(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        name = "SANDBOX"
        if size_ptr:
            capacity = utils_uc.ReadU32Le(self.uc, size_ptr)
            self._write_w_string(buf, name, capacity)
            self._write_u32(size_ptr, len(name))
        self._ret(1)

    def api_GetVersion(self) -> None:
        self._ret(0x0A000000)

    def api_GetVersionExA(self) -> None:
        info = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        if info:
            size = utils_uc.ReadU32Le(self.uc, info)
            self._write_u32(info + 4, 10)
            self._write_u32(info + 8, 0)
            self._write_u32(info + 12, 19045)
            self._write_u32(info + 16, 2)
            if size >= 156:
                self._write_bytes(info + 20, b"Service Pack 0\x00")
        self._ret(1)

    def api_GetLogicalDrives(self) -> None:
        self._ret(1 << 2)

    def api_GetDriveTypeA(self) -> None:
        self._ret(DRIVE_FIXED)

    def api_GetVolumeInformationA(self) -> None:
        volume_name = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        volume_size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        serial_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        max_component_ptr = self._stack_arg(0)
        flags_ptr = self._stack_arg(1)
        fs_name = self._stack_arg(2)
        fs_name_size = self._stack_arg(3)
        self._write_c_string(volume_name, "SANDBOX", volume_size)
        if serial_ptr:
            self._write_u32(serial_ptr, 0x1234ABCD)
        if max_component_ptr:
            self._write_u32(max_component_ptr, 255)
        if flags_ptr:
            self._write_u32(flags_ptr, 0)
        self._write_c_string(fs_name, "NTFS", fs_name_size)
        self._ret(1)

    def api_QueryDosDeviceA(self) -> None:
        buf = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        size = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        text = r"\\Device\\HarddiskVolume1"
        written = self._write_c_string(buf, text, size)
        self._ret(written)

    def api_SearchPathA(self) -> None:
        self._set_last_error(2)
        self._ret(0)

    def api_FindFirstFileA(self) -> None:
        self._set_last_error(2)
        self._ret(INVALID_HANDLE_VALUE)

    def api_FindFirstFileW(self) -> None:
        self._set_last_error(2)
        self._ret(INVALID_HANDLE_VALUE)

    def api_FindNextFileA(self) -> None:
        self._set_last_error(18)
        self._ret(0)

    def api_FindNextFileW(self) -> None:
        self._set_last_error(18)
        self._ret(0)

    def api_CreateFileA(self) -> None:
        path = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        self._ret(self._new_handle("file", path=path, pos=0, data=b""))

    def api_CreateFileW(self) -> None:
        path = self._read_w_string(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        self._ret(self._new_handle("file", path=path, pos=0, data=b""))

    def api_ReadFile(self) -> None:
        handle = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        buffer = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        to_read = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        bytes_read_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        info = self.handles.get(handle)
        data = b""
        if info is not None:
            data = info.meta.get("data", b"")
        chunk = data[:to_read].ljust(to_read, b"\x00")
        if buffer and to_read:
            self._write_bytes(buffer, chunk)
        if bytes_read_ptr:
            self._write_u32(bytes_read_ptr, min(len(data), to_read))
        self._ret(1)

    def api_WriteFile(self) -> None:
        bytes_to_write = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        bytes_written_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        if bytes_written_ptr:
            self._write_u32(bytes_written_ptr, bytes_to_write)
        self._ret(1)

    def api_SetFilePointerEx(self) -> None:
        distance = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        out_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        if out_ptr:
            self._write_u64(out_ptr, distance)
        self._ret(1)

    def api_GetFileSize(self) -> None:
        high_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        if high_ptr:
            self._write_u32(high_ptr, 0)
        self._ret(0)

    def api_GetFileInformationByHandle(self) -> None:
        info_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        if info_ptr:
            self._write_bytes(info_ptr, b"\x00" * 52)
        self._ret(1)

    def api_CreateFileMappingA(self) -> None:
        max_size_high = self._stack_arg(0)
        max_size_low = self._stack_arg(1)
        size = ((max_size_high & 0xFFFFFFFF) << 32) | (max_size_low & 0xFFFFFFFF)
        self._ret(self._new_handle("mapping", size=size))

    def api_MapViewOfFile(self) -> None:
        handle = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        requested = self._stack_arg(0)
        info = self.handles.get(handle)
        size = requested or (info.meta.get("size", 0x1000) if info else 0x1000)
        self._ret(self._alloc(size))

    def api_DeviceIoControl(self) -> None:
        out_bytes_ptr = self._stack_arg(2)
        if out_bytes_ptr:
            self._write_u32(out_bytes_ptr, 0)
        self._set_last_error(1)
        self._ret(0)

    def api_DuplicateHandle(self) -> None:
        out_handle_ptr = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        new_handle = self._new_handle("duplicated")
        if out_handle_ptr:
            self._write_u64(out_handle_ptr, new_handle)
        self._ret(1)

    def api_GetProcessTimes(self) -> None:
        creation = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        exit_time = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        kernel = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        user = self._stack_arg(0)
        for ptr in (creation, exit_time, kernel, user):
            if ptr:
                self._write_filetime(ptr)
        self._ret(1)

    def api_GetSystemTime(self) -> None:
        self._write_system_time(self._reg(unicorn.x86_const.UC_X86_REG_RCX), datetime.now(timezone.utc))
        self._ret(0)

    def api_GetLocalTime(self) -> None:
        self._write_system_time(self._reg(unicorn.x86_const.UC_X86_REG_RCX), datetime.now())
        self._ret(0)

    def api_GetSystemTimeAsFileTime(self) -> None:
        self._write_filetime(self._reg(unicorn.x86_const.UC_X86_REG_RCX))
        self._ret(0)

    def api_SystemTimeToFileTime(self) -> None:
        system_time_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        file_time_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RDX)
        if system_time_ptr and file_time_ptr:
            raw = self.uc.mem_read(system_time_ptr, 16)
            year, month, _, day, hour, minute, second, milliseconds = struct.unpack("<8H", raw)
            dt = datetime(year or 1970, max(month, 1), max(day, 1), hour, minute, second, milliseconds * 1000, tzinfo=timezone.utc)
            filetime = FILETIME_EPOCH + int(dt.timestamp() * 10_000_000)
            self._write_u64(file_time_ptr, filetime)
            self._ret(1)
            return
        self._ret(0)

    def api_GetTimeZoneInformation(self) -> None:
        info_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        if info_ptr:
            self._write_bytes(info_ptr, b"\x00" * 172)
        self._ret(TIME_ZONE_ID_UNKNOWN)

    def api_GetSystemInfo(self) -> None:
        info_ptr = self._reg(unicorn.x86_const.UC_X86_REG_RCX)
        if info_ptr:
            data = struct.pack(
                "<HHIQQQIIIHH",
                9,
                0,
                PAGE_SIZE,
                0x10000,
                0x7FFFFFFEFFFF,
                0xFF,
                8,
                0x24A,
                0x10000,
                6,
                0x3C03,
            )
            self._write_bytes(info_ptr, data)
        self._ret(0)

    def api_WideCharToMultiByte(self) -> None:
        src = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        char_count = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        dst = self._stack_arg(0)
        dst_size = self._stack_arg(1)
        text = self._read_w_string(src) if char_count == 0xFFFFFFFFFFFFFFFF else self.uc.mem_read(src, char_count * 2).decode("utf-16le", errors="ignore")
        encoded = text.encode("mbcs", errors="ignore")
        if dst and dst_size:
            self._write_bytes(dst, encoded[:dst_size])
        self._ret(len(encoded))

    def api_MultiByteToWideChar(self) -> None:
        src = self._reg(unicorn.x86_const.UC_X86_REG_R8)
        byte_count = self._reg(unicorn.x86_const.UC_X86_REG_R9)
        dst = self._stack_arg(0)
        dst_size = self._stack_arg(1)
        text = self._read_c_string(src) if byte_count == 0xFFFFFFFFFFFFFFFF else self.uc.mem_read(src, byte_count).decode("mbcs", errors="ignore")
        encoded = text.encode("utf-16le", errors="ignore")
        if dst and dst_size:
            self._write_bytes(dst, encoded[:dst_size * 2])
        self._ret(len(encoded) // 2)

    def api_CreateProcessW(self) -> None:
        process_info = self._stack_arg(5)
        proc_handle = self._new_handle("process")
        thread_handle = self._new_handle("thread")
        if process_info:
            self._write_u64(process_info + 0, proc_handle)
            self._write_u64(process_info + 8, thread_handle)
            self._write_u32(process_info + 16, 0x1337)
            self._write_u32(process_info + 20, 0x4242)
        self._ret(1)

    def api_ConvertThreadToFiber(self) -> None:
        self._ret(self._alloc(0x40))

    def api_DeleteFiber(self) -> None:
        self._ret(0)

    def api_GetProcAddress(self) -> None:
        proc_name = self._read_c_string(self._reg(unicorn.x86_const.UC_X86_REG_RDX))
        self._ret(self._make_proc_stub(1 if proc_name else 0))

    def api_RtlUnwindEx(self) -> None:
        self._ret(0)

    def api_SetErrorMode(self) -> None:
        self._ret(0)


def _get_state(uc: unicorn.Uc) -> SimApi:
    state = getattr(uc, "_sim_api_state", None)
    if state is None:
        state = SimApi(uc)
        setattr(uc, "_sim_api_state", state)
    return state


def simulate_import(uc: unicorn.Uc, api_name: str) -> bool:
    return _get_state(uc).dispatch(api_name)
