import utils_ida
from struct import unpack

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
    start = int('00007FF6E3F4FEEC', 16)

    while True:

        b = utils_ida.GetBytesFromEA(start, 4)
        length, ec = unpack('<HH', b)

        if length == 0:
            print('exit when length = 0')
            break

        utils_ida.DelItem(start, length)

        utils_ida.CreateWord(start)
        utils_ida.CreateWord(start + 2)

        utils_ida.CreateStr(start + 4, length - 4)
        utils_ida.CreateComment(start + 4, decodeText(utils_ida.GetBytesFromEA(start + 4, length - 4)).decode('utf-16le'))
        print(f'{start:016X} - {length} - {ec} - {decodeText(utils_ida.GetBytesFromEA(start + 4, length - 4)).decode('utf-16le')}')

        start += length

    pass

if __name__ == '__main__':
    main()
