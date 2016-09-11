import Dex

dex = Dex.Dex('classes2.dex')

dex.print_dex_header()
dex.getStrings().printAllEls()
dex.getTypes().printAllEls()
dex.getProtos().printAllEls()
dex.getFields().printAllEls()
dex.getMethods().printAllEls()
dex.getClassDefs().printAllEls()

classes = dex.getClasses()
for i in range(len(classes)):
    item = classes[i]
    print "[#%d] Class" % i
    item.printAllEl()