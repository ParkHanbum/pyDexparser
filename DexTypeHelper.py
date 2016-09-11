import struct

class DexTypeHelper():

    @staticmethod
    def CalcDecUnsignedLEB128(value):
        if value < (0x80):
            return 1
        elif value < (0x80 << 7):
            return 2
        elif value < (0x80 << 14):
            return 3
        return 4

    @staticmethod
    def readUnsignedLEB128(mm, offset):
        value = struct.unpack('<i', mm[offset:offset+4])[0]
        result = 0
        for i in range(4):
            curr = value & (0x000000ff << (i*8))
            curr = curr >> (i*8)
            result = result | ((curr & 0x7f) << (i * 7))
            if ((curr & 0x80) != 0x80): break
        return result

    @staticmethod
    def readSignedLed128(mm, offset):
        value = struct.unpack('<i', mm[offset:offset + 4])[0]
        result = 0
        signBits = -1
        for i in range(4):
            curr = value & (0x000000ff << (i * 8))
            curr = curr >> (i * 8)
            signBits <<= 7
            result = result | ((curr & 0x7f) << (i * 7))
            if ((curr & 0x80) != 0x80): break

        if (((signBits >> 1) & result) != 0):
            result |= signBits
        return result
