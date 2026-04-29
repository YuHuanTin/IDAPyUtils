"""
通用环境初始化：自动处理路径并清理本地模块缓存
必须最先调用
"""
import os
import sys
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

import utils
import struct

def decodeText(buf: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(buf)

    while i < n:
        val = 0
        shift = 0

        # 内层循环：解析变长编码 LEB128
        while i < n:
            b = buf[i]
            i += 1

            # (b & 0x7F) 提取低 7 位数据，并进行移位
            # & 0xFFFF 强制保持在 uint16_t 范围内，模拟溢出截断
            val = (val + ((b & 0x7F) << shift)) & 0xFFFF
            shift += 7

            # 如果最高位为 0，说明当前字符读取完毕
            if (b & 0x80) == 0:
                break

        # --- 核心修改在这里 ---
        # 此时的 val 就是一个 uint16_t
        # 我们直接将它转换成 2 个字节 (小端序) 并写入输出流
        out.extend(val.to_bytes(2, byteorder='little'))

    # 最终返回完整的、原生的 bytes 字节流
    return bytes(out)

def main():
    start = int('00007FF62A66FEEC', 16)

    while True:

        b = utils.GetBytesFromEA(start, 4)
        length, ec = unpack('<HH', b)

        if length == 0:
            print('exit when length = 0')
            break
        

        utils.DelItem(start, length)

        utils.CreateWord(start)
        utils.CreateWord(start + 2)

        utils.CreateStr(start + 4, length - 4)
        utils.CreateComment(start + 4, decodeText(utils.GetBytesFromEA(start + 4, length - 4)).decode('utf-16le'))
        print(f'{start:016X} - {length} - {ec} - {decodeText(utils.GetBytesFromEA(start + 4, length - 4)).decode('utf-16le')}')

        start += length

    pass

if __name__ == '__main__':
    main()
