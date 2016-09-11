import struct
import hashlib
import zlib
from StringItems import StringItems
from TypeItems import TypeItems
from ProtoItems import ProtoItems
from FieldItems import FieldItems
from MethodItems import MethodItems
from ClassDefItems import ClassDefItems
from collections import namedtuple
from Clazz import Clazz


class Dex:

    DexHeader = namedtuple("DexHeader", "magic checksum signature file_size header_size endian_tag link_size " +
                           "link_off map_off string_ids_size string_ids_off type_ids_size type_ids_off " +
                           "proto_ids_size proto_ids_off field_ids_size field_ids_off method_ids_size " +
                           "method_ids_off class_defs_size class_defs_off data_size data_off")

    def __init__(self, dex_file_path):
        dex_file = open(dex_file_path, 'rb')
        self.mm = dex_file.read()
        dex_file.close()
        self.classes = []
        self.parse_dex_header()
        self.parse_dex_parts()

    def parse_dex_header(self):
        magic = self.mm[0:8]
        checksum = struct.unpack('<L', self.mm[8:0xC])[0]
        signature = self.mm[0xC:0x20]
        file_size = struct.unpack('<L', self.mm[0x20:0x24])[0]
        header_size = struct.unpack('<L', self.mm[0x24:0x28])[0]
        endian_tag = struct.unpack('<L', self.mm[0x28:0x2C])[0]
        link_size = struct.unpack('<L', self.mm[0x2C:0x30])[0]
        link_off = struct.unpack('<L', self.mm[0x30:0x34])[0]
        map_off = struct.unpack('<L', self.mm[0x34:0x38])[0]
        string_ids_size = struct.unpack('<L', self.mm[0x38:0x3C])[0]
        string_ids_off = struct.unpack('<L', self.mm[0x3C:0x40])[0]
        type_ids_size = struct.unpack('<L', self.mm[0x40:0x44])[0]
        type_ids_off = struct.unpack('<L', self.mm[0x44:0x48])[0]
        proto_ids_size = struct.unpack('<L', self.mm[0x48:0x4C])[0]
        proto_ids_off = struct.unpack('<L', self.mm[0x4C:0x50])[0]
        field_ids_size = struct.unpack('<L', self.mm[0x50:0x54])[0]
        field_ids_off = struct.unpack('<L', self.mm[0x54:0x58])[0]
        method_ids_size = struct.unpack('<L', self.mm[0x58:0x5C])[0]
        method_ids_off = struct.unpack('<L', self.mm[0x5C:0x60])[0]
        class_defs_size = struct.unpack('<L', self.mm[0x60:0x64])[0]
        class_defs_off = struct.unpack('<L', self.mm[0x64:0x68])[0]
        data_size = struct.unpack('<L', self.mm[0x68:0x6C])[0]
        data_off = struct.unpack('<L', self.mm[0x6C:0x70])[0]

        if len(self.mm) != file_size:
            print "ERROR"

        self.dexHeader = self.DexHeader(magic, checksum, signature, file_size, header_size, endian_tag, link_size,
                                        link_off, map_off, string_ids_size, string_ids_off, type_ids_size, type_ids_off,
                                        proto_ids_size, proto_ids_off, field_ids_size, field_ids_off, method_ids_size,
                                        method_ids_off, class_defs_size, class_defs_off, data_size, data_off)

    def print_dex_header(self):
        print self.dexHeader

    def parse_dex_parts(self):
        self.string_id_list()
        self.type_id_list()
        self.proto_id_list()
        self.field_id_list()
        self.method_id_list()
        self.class_def_list()
        self.class_data_item()

    def string_id_list(self):
        self.strings = StringItems()
        self.strings.string_id_list(self.mm, self.dexHeader)

    def type_id_list(self):
        self.types = TypeItems()
        self.types.type_id_list(self.mm, self.dexHeader)

    def proto_id_list(self):
        self.protos = ProtoItems()
        self.protos.proto_id_list(self.mm, self.dexHeader)

    def field_id_list(self) :
        self.fields = FieldItems()
        self.fields.field_id_list(self.mm, self.dexHeader)

    def method_id_list(self):
        self.methods = MethodItems()
        self.methods.method_id_list(self.mm, self.dexHeader)

    def class_def_list(self) :
        self.classDefs = ClassDefItems()
        self.classDefs.class_def_list(self.mm, self.dexHeader)

    def class_data_item(self):
        for i in range(self.classDefs.size):
            clazz = Clazz(self.mm, self.classDefs.items[i])
            self.classes.append(clazz)

    def calcSignature(self):
        hash = hashlib.sha1()
        return hash(self.mm[32:len(self.mm)+1])

    def calcChecksum(self):
        zlib.adler32(self.mm[12:len(self.mm)+1])

    def getStrings(self):
        return self.strings

    def getTypes(self):
        return self.types

    def getProtos(self):
        return self.protos

    def getFields(self):
        return self.fields

    def getMethods(self):
        return self.methods

    def getClassDefs(self):
        return self.classDefs

    def getClasses(self):
        return self.classes