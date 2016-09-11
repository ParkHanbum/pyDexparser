import struct
from DexItem import DexItem
from collections import namedtuple


class TypeItems(DexItem):
    TypeItem = namedtuple("TypeItem", "type_off type_idx")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Type Item"

    def type_id_list(self, mm, dexHeader):
        type_ids_size = dexHeader.type_ids_size
        type_ids_off = dexHeader.type_ids_off
        self.size = type_ids_size
        self.offset = type_ids_off
        for idx in range(type_ids_size):
            type_idx = struct.unpack('<L', mm[type_ids_off + (idx * 4):type_ids_off + (idx * 4) + 4])[0]
            type_off = type_ids_off + (idx * 4)
            aTypeItem = self.TypeItem(type_off, type_idx)
            self.items.append(aTypeItem)  # index into the string_ids
