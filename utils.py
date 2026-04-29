from dataclasses import dataclass

import ida_funcs
import ida_gdl
import idautils
import idc

@dataclass
class SegmentInfo:
    start: int
    end: int
    len: int
    name: str

def GetEAFromName(name: str) -> int:
    '''
    通过函数名称获取程序地址
    :param name: 
    :return: 
    '''
    return idc.get_name_ea_simple(name)
    # return idc.get_name_ea(idc.BADADDR, name)

def GetFuncFromEA(ea: int) -> ida_funcs.func_t:
    '''
    通过地址获取函数对象
    :param ea: 
    :return: 
    '''
    return ida_funcs.get_func(ea)

def GetBytesFromEA(ea: int, len: int, usingDebuggerMemory: bool = False) -> bytes:
    '''
    通过地址获取数据
    :param ea: 
    :param len: 
    :param usingDebuggerMemory: 
    :return: 
    '''
    return idc.get_bytes(ea, len, usingDebuggerMemory)

def GetSegments() -> list[SegmentInfo]:
    '''
    获取程序段信息列表
    :return: 
    '''
    l = list(idautils.Segments())

    segmentInfos: list[SegmentInfo] = []
    for s in l:
        name = idc.get_segm_name(s)
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)

        if start != s:
            raise Exception(f'start address mismatch: {start} != {s}')

        segmentInfos.append(SegmentInfo(start=start, end=end, len=end - start, name=name))
    return segmentInfos

def GetCFGFromEA(ea: int) -> list[ida_gdl.BasicBlock]:
    '''
    获取程序基本块
    :param ea: 
    :return: 
    '''
    fc = ida_gdl.FlowChart(GetFuncFromEA(ea))
    return [n for n in fc]

def GetCFGImage(ea: int, filename: str, title: str = ''):
    '''
    获取程序 CFG 图像描述（https://dreampuf.github.io/GraphvizOnline/）
    :param ea: 
    :param filename: 
    :param title: 
    :return: 
    '''
    return ida_gdl.gen_flow_graph(filename, title, GetFuncFromEA(ea), 0, 0, gflags=ida_gdl.CHART_GEN_DOT)

def IsCode(ea: int):
    return idc.is_code(idc.get_full_flags(ea))

def CreateComment(ea: int, msg: str, shiftComment: bool = False):
    return idc.set_cmt(ea, msg, 1 if shiftComment else 0)

def CreateWord(ea: int):
    return idc.create_word(ea)

def CreateInst(ea: int):
    return idc.create_insn(ea)

def CreateStr(ea: int, len: int):
    return idc.create_strlit(ea, ea + len)

def DelItem(ea: int, len: int | None = None):
    """
    delete ea item as undefined
    :param ea: 
    :return: 
    """
    if len is None:
        return idc.del_items(ea)
    else:
        return idc.del_items(ea, idc.DELIT_SIMPLE, len)

def DelComment(ea: int, shiftComment: bool = False):
    return idc.set_cmt(ea, '', 1 if shiftComment else 0)

def PatchNop(ea: int, len: int):
    for i in range(len):
        idc.patch_byte(ea + i, 0x90)
    pass

def Patch(ea: int, bytes: bytes):
    for i in range(len(bytes)):
        idc.patch_byte(ea + i, bytes[i])
    pass

class CFGProcessor:
    @dataclass
    class BlockInfo:
        start: int
        end: int
        type: int
        numOfPreds: int
        predBlocks: list[tuple]
        numOfNexts: int
        nextBlocks: list[tuple]

    def __init__(self, cfgList: list[ida_gdl.BasicBlock]):
        self._listOfBlockInfos: list[self.BlockInfo] = []

        for cfg in cfgList:
            preds = [(p.start_ea, p.end_ea) for p in cfg.preds()]
            succs = [(s.start_ea, s.end_ea) for s in cfg.succs()]

            info = self.BlockInfo(
                start=cfg.start_ea,
                end=cfg.end_ea,
                type=cfg.type,
                numOfPreds=len(preds),
                predBlocks=preds,
                numOfNexts=len(succs),
                nextBlocks=succs
            )
            self._listOfBlockInfos.append(info)

    def GetNoPredBlocks(self):
        '''
        查找没有前驱的基本块
        :return: 
        '''

        noPreds = [b.start for b in self._listOfBlockInfos if b.numOfPreds == 0]
        return noPreds

    def GetNoNextBlocks(self):
        '''
        查找没有后续的基本块
        :return: 
        '''
        noNexts = [b.start for b in self._listOfBlockInfos if b.numOfNexts == 0]
        return noNexts
