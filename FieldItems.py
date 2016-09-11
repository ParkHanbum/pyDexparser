import struct
from DexItem import DexItem
from collections import namedtuple


class FieldItems(DexItem):
    FieldItem = namedtuple("FieldItem", "class_idx type_idx name_idx")
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Field Item"

    def field_id_list(self, mm, dexHeader):
        field_ids_size = dexHeader.field_ids_size
        field_ids_off = dexHeader.field_ids_off
        for idx in range(field_ids_size):
            class_idx = struct.unpack('<H', mm[field_ids_off + (idx * 8):field_ids_off + (idx * 8) + 2])[0]  # index into the type_ids
            type_idx = struct.unpack('<H', mm[field_ids_off + (idx * 8) + 2:field_ids_off + (idx * 8) + 4])[0]  # index into the type_ids
            name_idx = struct.unpack('<L', mm[field_ids_off + (idx * 8) + 4:field_ids_off + (idx * 8) + 8])[0]  # index into the string_ids
            aFieldItem = self.FieldItem(class_idx, type_idx, name_idx)
            self.items.append(aFieldItem)
