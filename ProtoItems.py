import struct
from DexItem import DexItem
from collections import namedtuple


class ProtoItems(DexItem):
    ProtoItem = namedtuple("ProtoItem", "shorty_idx return_type_idx parameters_off")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Proto Item"

    def proto_id_list(self, mm, dexHeader):
        proto_ids_size = dexHeader.proto_ids_size
        proto_ids_off = dexHeader.proto_ids_off
        self.size = proto_ids_size
        self.offset = proto_ids_off
        for idx in range(proto_ids_size):
            # index into the string_ids
            shorty_idx = struct.unpack('<L', mm[proto_ids_off + (idx * 12):proto_ids_off + (idx * 12) + 4])[0]
            # index into the type_ids
            return_type_idx = struct.unpack('<L', mm[proto_ids_off+(idx*12)+4:proto_ids_off+(idx*12)+ 8])[0]
            param_off = struct.unpack('<L', mm[proto_ids_off + (idx * 12) + 8:proto_ids_off + (idx * 12) + 12])[0]
            aProtoItem = self.ProtoItem(shorty_idx, return_type_idx, param_off)
            self.items.append(aProtoItem)
