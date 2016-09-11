
class DexItem:
    def __init__(self):
        self.tag = "Abstract Item"
        self.offset = 0
        self.size = 0
        self.items = []

    def getItems(self):
        return self.items

    def printAllEls(self):
        print self.tag
        print "[ItemOffset] " + format(self.offset, '08X')
        print "[ItemSize]   " + format(self.size, '08X')
        for i in range(len(self.items)):
            item = self.items[i]
            print '[%4d] %s' % (i, item)
