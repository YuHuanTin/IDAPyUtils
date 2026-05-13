from dataclasses import dataclass
from typing import Literal, Any

import x64dbg_automate

VALID_TYPES = {'cstr', 'wstr', 'u32ptr', 'u64ptr', 'u32', 'u64'}
VALID_OPTIONS = {'size_from', 'size'}  # see below `ParamType`

@dataclass
class ParamType:
    name: str  # see `VALID_TYPES`
    output: bool = False
    size: int | None = None
    size_from: str | None = None

@dataclass
class ApiInfo:
    name: str
    numberOfParams: int
    paramTypes: list[ParamType]
    retType: ParamType | None = None

@dataclass
class ParsedApiInfo:
    name: str
    padding: bool
    params: list[Any]
    ret: Any = None

class APIArgsCapturer:
    def __init__(self, path: str, client: x64dbg_automate.X64DbgClient,
                 callingConvention: Literal['fastcall'] = 'fastcall'):
        self.__path = path
        self.__apis = self.__read_api_sets()
        self.__callingConvention = callingConvention
        self.__client = client

        # 保存 onEnter 数据直到 onLeave
        self.__on_enter = True
        self.__cur_apiInfo: ApiInfo | None = None
        self.__cur_raw_args: list[int] = []
        self.__cur_parsedApiInfo: ParsedApiInfo | None = None

    def __read_args_by_calling_convention(self, apiInfo: ApiInfo) -> list[int]:
        match self.__callingConvention:
            case 'fastcall':
                rsp = self.__client.get_reg('rsp')
                return [
                    self.__client.get_reg(('rcx', 'rdx', 'r8', 'r9')[index])
                    if index < 4 else self.__client.read_qword(rsp + 0x28 + (index - 4) * 8)
                    for index in range(apiInfo.numberOfParams)
                ]
            case _:
                raise RuntimeError(f'unsupported calling convention: {self.__callingConvention}')

    def __read_ZeroTerminedStr(self, addr: int, sep: bytes, size: int | None = None):
        data = bytearray()

        if size:
            return self.__client.read_memory(addr, size)

        thunk_size = 256
        thunks = 0

        while True:
            c = self.__client.read_memory(addr + thunks * thunk_size, thunk_size)
            terminator_index = c.find(sep)
            if terminator_index != -1:
                data.extend(c[:terminator_index])
                break
            else:
                data.extend(c)
                thunks += 1
        return data

    def __read_scalar_param_by_type(self, paramType: ParamType, value: int) -> Any:
        if paramType.name == 'u32':
            return value & 0xffffffff
        if paramType.name == 'u64':
            return value
        # when value = nullptr, do not read ptr
        if paramType.name == 'u32ptr':
            return self.__client.read_dword(value) if value else None
        if paramType.name == 'u64ptr':
            return self.__client.read_qword(value) if value else None
        return None

    def __read_param_size(self, paramType: ParamType) -> int | None:
        if paramType.size is not None:
            return paramType.size

        if paramType.size_from is not None:
            if paramType.size_from.lower() == 'ret':
                return self.__read_param(-1)
            index = int(paramType.size_from[3:]) - 1
            if not 0 <= index < len(self.__cur_raw_args):
                return None

            paramType = self.__cur_apiInfo.paramTypes[index]
            value = self.__cur_raw_args[index]
            return self.__read_scalar_param_by_type(paramType, value)
        return None

    def __read_param_by_type(self, paramType: ParamType, value: int) -> Any:
        scalar = self.__read_scalar_param_by_type(paramType, value)
        if paramType.name in {'u32', 'u64'}:
            return scalar
        if value == 0:
            return f'optional'
        size = self.__read_param_size(paramType)
        if size is not None and paramType.name in {'u32ptr', 'u64ptr'}:
            if size == 0:
                return f'size0'
            return self.__client.read_memory(value, size)
        if paramType.name == 'u32ptr':
            return scalar
        if paramType.name == 'u64ptr':
            return scalar
        if paramType.name == 'cstr':
            return (self.__read_ZeroTerminedStr(value, b'\x00', size)
                    .decode('mbcs', errors='replace'))
        if paramType.name == 'wstr':
            return (self.__read_ZeroTerminedStr(value, b'\x00\x00', size * 2 if size is not None else None)
                    .decode('utf-16-le', errors='replace'))
        return None

    def __read_param(self, index: int) -> Any:
        if index == -1:
            return self.__read_param_by_type(self.__cur_apiInfo.retType, self.__client.get_reg('rax'))
        t = self.__cur_apiInfo.paramTypes[index]
        if t.output and self.__on_enter:
            return f'raw({self.__cur_raw_args[index]})'
        return self.__read_param_by_type(t, self.__cur_raw_args[index])

    def onEnter(self, apiName: str) -> ParsedApiInfo:
        self.__on_enter = True
        apis = [info for info in self.__apis if info.name == apiName]
        if len(apis) > 1:
            raise RuntimeError(f'API {apiName} not found or duplicated in API set')

        if len(apis) == 0:
            print(f'warning: no API found called: {apiName}')
            return None

        self.__cur_apiInfo = apis[0]
        self.__cur_raw_args = self.__read_args_by_calling_convention(self.__cur_apiInfo)
        self.__cur_parsedApiInfo = ParsedApiInfo(
            name=self.__cur_apiInfo.name,
            padding=self.__cur_apiInfo.retType is not None or
                    any(paramType.output for paramType in self.__cur_apiInfo.paramTypes),
            params=[self.__read_param(index)
                    for index in range(self.__cur_apiInfo.numberOfParams)]
        )
        return self.__cur_parsedApiInfo

    def onLeave(self) -> ParsedApiInfo:
        self.__on_enter = False
        if self.__cur_apiInfo is None:
            raise RuntimeError('onLeave called without onEnter or API not found in onEnter')

        if self.__cur_parsedApiInfo is None:
            raise RuntimeError('internal error: parsedApiInfo is None in onLeave')

        for index, paramType in enumerate(self.__cur_apiInfo.paramTypes):
            if paramType.output:
                self.__cur_parsedApiInfo.params[index] = self.__read_param(index)
        if self.__cur_apiInfo.retType is not None:
            self.__cur_parsedApiInfo.ret = self.__read_param(-1)
        self.__cur_parsedApiInfo.padding = False
        return self.__cur_parsedApiInfo

    @staticmethod
    def __split_top_level(text: str, sep: str = ',') -> list[str]:
        parts = []
        depth = 0
        start = 0
        for index, ch in enumerate(text):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth < 0:
                    raise RuntimeError(f'unmatched ")" in: {text}')
            elif ch == sep and depth == 0:
                parts.append(text[start:index].strip())
                start = index + 1
        if depth != 0:
            raise RuntimeError(f'unmatched "(" in: {text}')
        parts.append(text[start:].strip())
        return parts

    @staticmethod
    def __parse_param_type(text: str) -> ParamType:
        text = text.strip()
        if not text:
            raise ValueError('empty param type')

        if '(' in text:
            if not text.endswith(')'):
                raise ValueError(f'bad option syntax: {text}')
            name, options_text = text.split('(', 1)
            options_text = options_text[:-1]
        else:
            name = text
            options_text = ''

        name = name.strip()
        if name not in VALID_TYPES:
            raise ValueError(f'bad param type: {name}')

        param = ParamType(name)
        if not options_text:
            return param

        seen_options = set()
        for item in APIArgsCapturer.__split_top_level(options_text):
            if not item:
                print('warning: empty option syntax')
                continue
            if item == 'output':
                param.output = True
                continue
            key, sep, value = item.partition('=')
            if not sep:
                raise ValueError(f'bad option syntax: {item}')
            key = key.strip().lower()
            value = value.strip()
            if key not in VALID_OPTIONS:
                raise ValueError(f'bad option: {key}')
            if key in seen_options:
                raise ValueError(f'duplicate option: {key}')
            seen_options.add(key)

            if key == 'size_from':
                if (value.strip().lower() != 'ret' and
                        (not value.startswith('arg') or not value[3:].isdigit() or int(value[3:]) < 1)):
                    raise ValueError(f'size_from must be argN, N starts from 1, got {value}')
                param.size_from = value
            elif key == 'size':
                param.size = int(value, 0)
        return param

    def __read_api_sets(self):
        apiInfos: list[ApiInfo] = []

        with open(self.__path, 'r') as f:
            for line_no, line in enumerate(f, 1):
                line = line.split('#', 1)[0].strip()  # remove comment
                if not line:
                    continue

                name, line = line.split(':', 1)

                retTypePos = line.rfind(';')
                retType = None
                if retTypePos != -1:
                    retType = self.__parse_param_type(line[retTypePos + 1:])
                    retType.output = True
                    line = line[:retTypePos]

                params = self.__split_top_level(line)
                numParams = int(params[0])
                paramTypes = params[1:]

                if numParams != len(paramTypes):
                    raise RuntimeError(
                        f'arg count mismatch at line {line_no}, expected {numParams} but got {len(paramTypes)}')

                apiInfos.append(ApiInfo(name, numParams, [self.__parse_param_type(t) for t in paramTypes], retType))
        return apiInfos

# EnumDeviceDrivers
# GetVolumeInformationA
# GetDeviceDriverBaseNameA
