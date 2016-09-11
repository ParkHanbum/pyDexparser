import struct
from DexItem import DexItem
from collections import namedtuple


class MethodItems(DexItem):
    ClassDefItem = namedtuple("MethodItem", "class_idx proto_idx name_idx")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Method Item"

    def method_id_list(self, mm, dexHeader):
        method_ids_size = dexHeader.method_ids_size
        method_ids_off = dexHeader.method_ids_off
        self.size = method_ids_size
        self.offset = method_ids_off

        for idx in range(method_ids_size):
            class_idx = struct.unpack('<H', mm[method_ids_off + (idx * 8):method_ids_off + (idx * 8) + 2])[0]  # index into the type_ids
            proto_idx = struct.unpack('<H', mm[method_ids_off + (idx * 8) + 2:method_ids_off + (idx * 8) + 4])[0]  # index into the proto_ids
            name_idx = struct.unpack('<L', mm[method_ids_off + (idx * 8) + 4:method_ids_off + (idx * 8) + 8])[0]  # index into the string_ids
            aClassDefItem = self.ClassDefItem(class_idx, proto_idx, name_idx)
            self.items.append(aClassDefItem)
