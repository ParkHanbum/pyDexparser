import struct
from DexItem import DexItem
from collections import namedtuple


class ClassDefItems(DexItem):
    ClassDefItem = namedtuple("ClassDefItem", "class_idx access_flags superclass_idx interfaces_off " +
                                              "source_file_idx annotations_off class_data_off static_values_off")
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Class Def Item"

    def class_def_list(self, mm, dexHeader):
        class_size = dexHeader.class_defs_size
        class_off = dexHeader.class_defs_off
        self.size = class_size
        self.offset = class_off
        for idx in range(class_size):
            # index into the type_ids
            class_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 0:class_off + (idx * 0x20) + 4])[0]
            # access_flags
            access_flags = struct.unpack('<L', mm[class_off + (idx * 0x20) + 4:class_off + (idx * 0x20) + 8])[0]
            # index into the type_ids
            superclass_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 8:class_off + (idx * 0x20) + 12])[0]
            # offset in data section below "type_list"
            interfaces_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 12:class_off + (idx * 0x20) + 16])[0]
            # index into the string_ids
            source_file_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 16:class_off + (idx * 0x20) + 20])[0]
            # offset in data section "annotations_directory_item" below
            annotations_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 20:class_off + (idx * 0x20) + 24])[0]
            # offset in data section "class_data_item" below
            class_data_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 24:class_off + (idx * 0x20) + 28])[0]
            # offset in data section "encoded_array_item" below
            static_values_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 28:class_off + (idx * 0x20) + 32])[0]

            aClassDefItem = self.ClassDefItem(class_idx, access_flags, superclass_idx, interfaces_off,
                                              source_file_idx, annotations_off, class_data_off, static_values_off)
            self.items.append(aClassDefItem)
