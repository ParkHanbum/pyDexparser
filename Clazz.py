import struct
from DexTypeHelper import DexTypeHelper
from collections import namedtuple
from CodeItem import CodeItem


class Clazz:

    DexClassDataHeader = namedtuple("DexClassDataHeader", "staticFieldSize instanceFieldsSize " +
                                                          "directMethodsSize virtualMethodsSize")
    DexField = namedtuple("DexField", "fieldIdx accessFlags")
    DexMethod = namedtuple("DexMethod", "methodIdx accessFlags codeOff")
    DexClassData = namedtuple("DexClassData", "DexClassDataHeader DexField_staticFields DexField_instanceFields " +
                              "DexMethod_directMethods DexMethod_virtualMethods")

    def __init__(self, mm, aClassDefItem):
        self.classDefinition = aClassDefItem
        self.staticFields = []
        self.instanceFields = []
        self.directMethods = []
        self.virtualMethods = []
        self.codeItems = []
        self.parseClasses(mm, aClassDefItem)
        if aClassDefItem.class_data_off != 0:
            self.parseCodes()
        else:
            self.parseClassWithNoData()

    def readUnsignedLEB128(self):
        value = DexTypeHelper.readUnsignedLEB128(self.mm, self.clazzOff)
        self.clazzOff = self.clazzOff + DexTypeHelper.CalcDecUnsignedLEB128(value)
        return value

    def parseClassWithNoData(self):
        static_fields_size = 0
        instance_fields_size = 0
        direct_methods_size = 0
        virtual_methods_size = 0

    def parseClasses(self, mm, aClassDefItem):
        clazzOff = aClassDefItem.class_data_off
        self.mm = mm
        self.clazzOff = clazzOff

        static_fields_size = self.readUnsignedLEB128()
        instance_fields_size = self.readUnsignedLEB128()
        direct_methods_size = self.readUnsignedLEB128()
        virtual_methods_size = self.readUnsignedLEB128()

        for idx in range(static_fields_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            aDexField = self.DexField(fieldIdx, accessFlags)
            self.staticFields.append(aDexField)

        for idx in range(instance_fields_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            aDexField = self.DexField(fieldIdx, accessFlags)
            self.instanceFields.append(aDexField)

        for idx in range(direct_methods_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            codeOff = self.readUnsignedLEB128()
            aDexMethod = self.DexMethod(fieldIdx, accessFlags, codeOff)
            self.directMethods.append(aDexMethod)

        for idx in range(virtual_methods_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            codeOff = self.readUnsignedLEB128()
            aDexMethod = self.DexMethod(fieldIdx, accessFlags, codeOff)
            self.virtualMethods.append(aDexMethod)

        # DexClassDataHeader
        aDexClassDataHeader = self.DexClassDataHeader(static_fields_size, instance_fields_size,
                                                      direct_methods_size, virtual_methods_size)

        self.dexClassData = self.DexClassData(aDexClassDataHeader, self.staticFields, self.instanceFields
                                              , self.directMethods, self.virtualMethods)

    def parseCodes(self):
        for i in range(len(self.directMethods)):
            method = self.directMethods[i]
            if method.codeOff != 0:
                aCodeItem = CodeItem(self.mm, self.directMethods[i])
                self.codeItems.append(aCodeItem)
        for i in range(len(self.virtualMethods)):
            method = self.virtualMethods[i]
            if method.codeOff != 0:
                aCodeItem = CodeItem(self.mm, self.virtualMethods[i])
                self.codeItems.append(aCodeItem)

    def printAllEl(self):
        print self.dexClassData
        for i in range(len(self.codeItems)):
            self.codeItems[i].printAllEl()
        print
