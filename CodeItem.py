import struct
from collections import namedtuple
from DexTypeHelper import DexTypeHelper


class CodeItem:

    code_item = namedtuple("CodeItem", "registersSize insSize outSize tries_size debug_info_off insns_size insns")
    try_item = namedtuple("TryItem", "startAddr insnCount handlerOff")
    encoded_catch_handler_list = namedtuple("HandlerList", "startAddr insnCount handlerOff")
    dex_catch_handler = namedtuple("DexCatchHandler", "size typeIdx address")

    def __init__(self, mm, aDexMethod):
        self.mm = mm
        self.DexMethod = aDexMethod
        self.tryItems = []
        self.handlers = []
        self.parseCodeItemHeader(self.mm, self.DexMethod)

    def parseCodeItemHeader(self, mm, DexMethod):
        offset = DexMethod.codeOff
        registers_size = struct.unpack('<H', mm[offset:offset + 2])[0]
        ins_size = struct.unpack('<H', mm[offset + 2:offset + 4])[0]
        outs_size = struct.unpack('<H', mm[offset + 4:offset + 6])[0]
        tries_size = struct.unpack('<H', mm[offset + 6:offset + 8])[0]
        debug_info_off = struct.unpack('<I', mm[offset + 8:offset + 12])[0]
        insns_size = struct.unpack('<I', mm[offset + 12:offset + 16])[0]
        insns = mm[offset+16: offset+16+(insns_size * 2)]

        self.codeItem = self.code_item(registers_size, ins_size, outs_size,
                                        tries_size, debug_info_off, insns_size, insns)

        offset = offset + 16 + (insns_size * 2)
        if offset & 3 != 0:
            offset = offset + 2

        for i in range(tries_size):
            try_startAddr = struct.unpack('<I', mm[offset:offset+4])[0]
            insn_count = struct.unpack('<H', mm[offset+4:offset+6])[0]
            handler_off = struct.unpack('<H', mm[offset+6:offset+8])[0]
            aTryitem = self.try_item(try_startAddr, insn_count, handler_off)
            self.tryItems.append(aTryitem)
            offset = offset + 8

        for i in range(len(self.tryItems)):
            item = self.tryItems[i]
            handlerOff = item.handlerOff
            catchesAll = False

            """
            offset = offset + handlerOff
            encoded_catch_handler_list_size = DexTypeHelper.readUnsignedLEB128(mm, offset)
            for idx in range(encoded_catch_handler_list_size):
                encoded_catch_handler_list_size_len = \
                    DexTypeHelper.CalcDecUnsignedLEB128(encoded_catch_handler_list_size)

                offset = offset + encoded_catch_handler_list_size_len
                encoded_catch_handler_size = DexTypeHelper.readSignedLed128(mm, offset)

                if encoded_catch_handler_size <= 0:
                    catchesAll = True
                    encoded_catch_handler_size *= -1
                else:
                    catchesAll = False

                for encoded_idx in range(encoded_catch_handler_size):
                    encoded_catch_handler_size_len = DexTypeHelper.CalcDecUnsignedLEB128(encoded_catch_handler_size)
                    offset = offset + encoded_catch_handler_size_len

                    typeIdx = DexTypeHelper.readUnsignedLEB128(mm, offset)
                    typeIdx_size = DexTypeHelper.CalcDecUnsignedLEB128(typeIdx)
                    offset = offset + typeIdx_size
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset)

            """

            count = DexTypeHelper.readSignedLed128(mm, offset + handlerOff)
            count_size = DexTypeHelper.CalcDecUnsignedLEB128(count)

            if count <= 0:
                catchesAll = True
                count *= -1
            else:
                catchesAll = False

            for idx in range(count, -1, -1):
                if idx == 0:
                    if catchesAll == True:
                        catchesAll = False
                        typeIdx = 0xffffffff
                    else:
                        break
                else:
                    typeIdx = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size)

                if typeIdx == 0xffffffff:
                    typeIdx_size = 0
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size)
                else:
                    typeIdx_size = DexTypeHelper.CalcDecUnsignedLEB128(typeIdx)
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size + typeIdx_size)

                handler_address_size = DexTypeHelper.CalcDecUnsignedLEB128(handler_address)
                self.handlers.append(self.dex_catch_handler(offset + handlerOff + count_size + typeIdx_size, typeIdx, handler_address))
                handlerOff = handlerOff + count_size + typeIdx_size + handler_address_size



    def printAllEl(self):
        print self.codeItem
        for i in range(len(self.tryItems)):
            item = self.tryItems[i]
            print "[%02d] : %04x - %04x  %04x" % (i, item.startAddr, item.startAddr + item.insnCount, item.handlerOff)

        for i in range(len(self.handlers)):
            item = self.handlers[i]
            print "[%02d] : %d  %04x  %04x" % (i, item.size, item.typeIdx, item.address)
