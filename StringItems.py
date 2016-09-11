from DexItem import DexItem
import struct
from collections import namedtuple
from DexTypeHelper import DexTypeHelper


class StringItems(DexItem):
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "String Item"

    def string_id_list(self, mm, dexHeader):
        string_ids_size = dexHeader.string_ids_size
        string_ids_off = dexHeader.string_ids_off
        self.size = string_ids_size
        self.offset = string_ids_off
        for idx in range(string_ids_size):
            off = struct.unpack('<L', mm[string_ids_off + (idx * 4):string_ids_off + (idx * 4) + 4])[0]
            utf16_size = (DexTypeHelper.readUnsignedLEB128(mm, off))
            if utf16_size <= 0:
                c_char = " "
            else:
                utf16_size_len = DexTypeHelper.CalcDecUnsignedLEB128(utf16_size)
                c_char = mm[off + utf16_size_len:off + utf16_size_len + utf16_size]
            self.items.append(c_char)
