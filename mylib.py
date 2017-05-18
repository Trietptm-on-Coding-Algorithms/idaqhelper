import idc
import inspect
import idaapi

def isRawPtr(obj):
    return isinstance(obj, rawPointer)

def isString(obj):
    return type(obj) is str

def terminate():
    import sys
    sys.exit()
    
def screenEA():
    return idaapi.get_screen_ea()

def Decompile(ea = screenEA()):
    return idaapi.decompile(ea)

def ask(askType, defaultVal, prompt):
    if askType is int or askType is long:
        return idc.AskLong(defaultVal, prompt)
    elif askType is str:
        return idc.AskStr(defaultVal, prompt)
    elif askType is bool:
        result = idc.AskYN(defaultVal, prompt)
        return bool(result) if result != -1 else None
    elif askType is file:
        typeAssert(defaultVal, bool)
        fname = idc.AskFile(defaultVal, "", prompt)
        if not isString(fname):
            return None
        return open(fname, "w" if defaultVal else "r")

def getCallerName(depth = 0):
    return inspect.stack()[2 + depth][3]

def warn(str):
    idc.Warning(str)

def validPrimitiveSize(sz):
    return sz == 1 or sz == 2 or sz == 4 or sz == 8

class rawPointer(object):
    
    def __init__(self, addr, sz):
        self.addr = addr
        self.sz = sz
        if not validPrimitiveSize(sz):
            warn("Bad size passed to rawPointer.__init__. Caller was " + getCallerName() + ".")
            terminate()
            
    
    @staticmethod
    def getPtrType(sz):
        import ctypes
        if sz == 1:
            return ctypes.c_char
        elif sz == 2:
            return ctypes.c_short
        elif sz == 4:
            return ctypes.c_int
        elif sz == 8:
            return ctypes.c_longlong
        else:
            print "Unhandled size in getPtrType. Size was " + str(sz) + "."
        return None
    
    def __eq__(self, other):
        return False if not isRawPtr(other) else self.addr == other.addr
    
    def __neq__(self, other):
        return True if not isRawPtr(other) else self.addr != other.addr
    
    def __lt__(self, other):
        return False if not isRawPtr(other) else self.addr < other.addr   
    
    def __gt__(self, other):
        return False if not isRawPtr(other) else self.addr > other.addr   
    
    def __le__(self, other):
        return False if not isRawPtr(other) else self.addr <= other.addr   
    
    def __ge__(self, other):
        return False if not isRawPtr(other) else self.addr >= other.addr  
    
    def __nonzero__(self):
        return bool(self.addr)
    
    def __call__(val = None):
        import ctypes
        ptrType = rawPointer.getPtrType(self.sz)
        castPtr = ctypes.cast(self.addr, ctypes.POINTER(ptrType))
        if val is None:
            return castPtr[0]
        else: 
            castPtr[0] = val
            return val
        
    def __getitem__(self, idx):
        import ctypes
        castPtr = ctypes.cast(self.addr, ctypes.POINTER(rawPointer.getPtrType(self.sz)))
        return castPtr[idx]
    
    def __setitem__(self, idx, val):
        import ctypes
        ptrType = rawPointer.getPtrType(self.sz)
        castPtr = ctypes.cast(self.addr, ctypes.POINTER(ptrType))
       
        valcast = ptrType(val)
        castPtr[idx] = valcast
        return valcast

def pointer_cast(ptr, size):
    return rawPointer(ptr, size) if not isRawPtr(ptr) else rawPointer(ptr.addr, size)
    
def nextHead(ea):
    return idc.BADADDR if warnBad(ea) else idc.NextHead(ea, idc.BADADDR)

def getFunctionEnd(ea):
    return idc.BADADDR if warnBad(ea) else idc.GetFunctionAttr(ea, idc.FUNCATTR_END)

def getFunctionStart(ea):
    return idc.BADADDR if warnBad(ea) else idc.GetFunctionAttr(ea, idc.FUNCATTR_START)

def getFunctionSize(ea):
    func = idaapi.get_func(ea)
    return 0 if warnBad(ea) else (func.endEA - func.startEA)

def jumpInDisasm(ea):
    return False if warnBad(ea) else idc.Jump(ea)

def getFunctionFrame(ea):
    return -1 if warnBad(ea) else idc.GetFunctionAttr(ea, FUNCATTR_FRAME)

def getFunctionName(ea):
    return "" if warnBad(ea) else (idc.Name(getFunctionStart(ea)))

def isFinalInsn(ea):
    return False if warnBad(ea) else nextHead(ea) == getFunctionEnd(ea)

def mnemAt(ea):
    return None if warnBad(ea) else idc.GetMnem(ea)

def operandAt(ea, index):
    return None if warnBad(ea) or index < 0 else idc.GetOpnd(ea, index)
#new version
def isBad(value):
    vType = type(value)
    return value == idc.BADADDR if (vType is int or vType is long) else len(value) == 0
                                        
#calls isBad and warns the user if it returns true
#uses inspect.stack() to get the caller's name for debugging
def warnBad(value, info = None):
    isbad = isBad(value)
    #vType = type(value)
    #isbad = (value == -1 if vType is int else len(value) == 0) 
    if not isbad:
        return False
    callerName = ""
    try:
        callerName = inspect.stack()[1][3]
    except IndexError as e:
        callerName = "(unknown)"
    print "Bad value in function " + callerName + "."
    if info is not None:
        print "Caller provided info: " + info
    return True

def getFunctionFlags(ea):
    #return 0 if warnBad(ea) else idc.GetFunctionAttr(ea, idc.FUNCATTR_FLAGS)
    return 0 if warnBad(ea) else idc.GetFunctionFlags(ea)

def setFunctionFlags(ea, flags):
    return False if warnBad(ea) else idc.SetFunctionFlags(ea, flags) != 0
    

def noretFlagSet(flags):
    return (flags & idc.FUNC_NORET) != 0

def clearNoreturnFlag(flags):
    return (flags & (~idc.FUNC_NORET))

def getNextFunction(ea):
    return idc.BADADDR if warnBad(ea) else idc.NextFunction(ea)

def getFirstFunction():
    return getNextFunction(0)

def getPreviousFunction(ea):
    return idc.PrevFunction(ea)

def getLastFunction():
    return getPreviousFunction(idc.BADADDR)

def getFunctionName(ea):
    return None if warnBad(ea) else idc.GetFunctionName(ea)

def addrInFunction(ea):
    return False if isBad(ea) else len(idc.GetFunctionName(ea)) != 0

def hasNextFunction(ea):
    return False if isBad(ea) else not isBad(idc.NextFunction(ea))

def hasPrecedingFunction(ea):
    return False if isBad(ea) else not isBad(idc.PrevFunction(ea))

def readByte(ea):
    return idc.Byte(ea) & 0xFF

def isByte(ea, val):
    return (idc.Byte(ea) & 0xFF) == val

def readWord(ea):
    return idc.Word(ea) & 0xFFFF

def isWord(ea, val):
    return (idc.Word(ea) & 0xFFFF) == val

def readDword(ea):
    return idc.Dword(ea)

def isDword(ea, val):
    return idc.Dword(ea) == val

class Memory(object):
    
    @staticmethod
    def refresh():
        idc.RefreshDebuggerMemory()
        
    @staticmethod
    def read(ea, size = 4):
        val = 0
        if size == 1:
            val = idc.DbgByte(ea)
        elif size == 2:
            val = idc.DbgWord(ea)
        elif size == 4:
            val = idc.DbgDword(ea)
        else:
            fatalError("Bad size encountered in Memory.read")
        return val
    @staticmethod
    def call(ea, *args):
        result = idc.Appcall(ea, 0, *args)
        return result
    
class Registers(object):
    @staticmethod
    def get(name):
        return idc.GetRegValue(name)
    
    @staticmethod
    def set(name, value):
        return idc.SetRegValue(value, name)

def waitForDebuggerEvent():
    return idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)

class typename(idaapi.tinfo_t):
    def __init__(self):
        idaapi.tinfo_t.__init__(self)


class idamember(object):
    def __init__(self, sid, offs):
        self.offs = offs
        #sid = struc
        name = None
        substruct = -1
        size = 0
        
        if not warnBad(sid):
            #struc = idaapi.get_struc(sid)
            #member = idaapi.get_member(struc, offs)
            
            name = idc.GetMemberName(sid, offs)
            substruct = idc.GetMemberStrId(sid, offs)
            size = idc.GetMemberSize(sid, offs)
            #name = idaapi.get_member_name(member.id)
            #substruct = idaapi.get_sptr(member)
            #size = idaapi.get_member_size(member)
            
        self.name = name
        self.struc = substruct
        self.size = size
        
    def __str__(self):
        return "idamember: {name = " + str(self.name) + ", struc = " + str(self.struc) + ", size = " + str(self.size) + "}"

class idastruct(object):
    def __init__(self, name):
        sid = -1
        nametype = type(name)
        if nametype is str:
            self.name = name
            sid = idaapi.get_struc_id(name)
        elif nametype is int or nametype is long:
            sid = name
            self.name = idaapi.get_struc_name(sid)
        
        self.sid = sid
        ssize = 0
        memberlist = None
        offs = 0
        
        if not warnBad(sid):
            struc = idaapi.get_struc(sid)
            ssize = idaapi.get_struc_size(sid)
            #memberqty = idc.GetMemberQty(sid)
            memberqty = struc.memqty
            memberlist = [None] * memberqty
            for i in range(0, memberqty):
                #memberlist.append(idamember(sid, offs))
                memberlist[i] = idamember(sid, offs)
                offs = idaapi.get_struc_next_offset(struc, offs)
        self.size = ssize
        self.members = memberlist
        
    def __len__(self):
        return len(self.members)
    
    def __getitem__(self, idx):
        idxtype = type(idx)
        if idxtype is int or idxtype is long:
            return self.members[idx]
        elif idxtype is str:
            for member in self:
                if member.name == idx:
                    return member
            return None
        else:
            warn("Bad index type in idastruct.__getitem__. Type was " + str(type(idx)) + ".")
            terminate()
        
    @staticmethod
    def getID(value):
        if isinstance(value, idastruct):
            return value.sid
        elif type(value) is int:
            return value
        else:
            return -1

def pyPeek(addr, sz):
    return pointer_cast(addr, sz)[0]

class structPrinter(object):
    
    def __init__(self):
        self.text = ""
        
    def __str__(self):
        return self.text
    
    def printTo(self, membername, value, address, nestingCount):
        for i in range(0, nestingCount):
            self.text += " "
        self.text += (membername + ": " + str(value) + ".\n")
        return True
def typeAssert1(obj, t1):
    return type(obj) is t1

def anyType(obj, *ts):
    objType = type(obj)
    for t in ts:
        if objType is t:
            return True
    return False

#warns the user and exits if it is not a valid type
def typeAssert(obj, *ts):
    objType = type(obj)
    for t in ts:
        if objType is t:
            return
    warn("typeAssert failed. Expected types: (" + str(ts) + "). Type was " + str(type(obj)) + ".")
    terminate()

def isFunction(obj):
    return hasattr(obj, '__call__')

def assertFunction(obj):
    if not isFunction(obj):
        terminate()
        
def instanceAssert(obj, *ts):
    for t in ts:
        if isinstance(obj, t):
            return
    terminate()
    
    
def printStructAt(readFunc, addr, struct_identity, printer, nested):
    
    assertFunction(readFunc)
    typeAssert(addr, int, long)
    typeAssert(struct_identity, int, long, str)
    instanceAssert(printer, structPrinter)
    typeAssert(nested, int, long)
    
    ty = idastruct(struct_identity)
    for member in ty:
        memStruc = member.struc
        
        if int(memStruc) != -1:
            printStructAt(readFunc, addr + member.offs, memStruc, printer, nested + 1)    
        else:
            if validPrimitiveSize(member.size):
                printer.printTo(member.name, readFunc(addr + member.offs, member.size), addr + member.offs, nested)
    return ty.name + " at address " + hex(addr) + ": \n" + str(printer)

def printStructDbg(addr, struct_name):
    return printStructAt(Memory.read, addr, struct_name, structPrinter(), 0)

def printStructPy(addr, struct_name):
    return printStructAt(pyPeek, addr, struct_name, structPrinter(), 0)

def getFirstStructIdx():
    return idaapi.get_first_struc_idx()

def getLastStructIdx():
    return idaapi.get_last_struc_idx()

def getNextStructIdx(idx):
    return idaapi.get_next_struc_idx(idx)

def getPreviousStructIdx(idx):
    return idaapi.get_prev_struc_idx(idx)

def getStructIdFromIdx(idx):
    return idaapi.get_struc_by_idx(idx)


class Structures(object):
    def __init__(self):
        self.first = int(getFirstStructIdx())
        self.last = int(getLastStructIdx())
        self.size = self.last - self.first
        
    def __len__(self):
        return self.size
    
    def __getitem__(self, idx):
        s = idaapi.get_struc_by_idx(idx)
        return idastruct(s) if s != idc.BADADDR else None
    
def foreachStructure(struct_iterator, *additionalArgs):
    assertFunction(struct_iterator)
    structures = Structures()
    for struct in structures:
        if struct is not None:
            if not struct_iterator(struct, *additionalArgs):
                break
            
def foreachStructureNameAndSize(struct_iterator, *additionalArgs):
    assertFunction(struct_iterator)
    first = int(getFirstStructIdx())
    last = int(getLastStructIdx())
    for i in range(first, last):
        sid = idaapi.get_struc_by_idx(i)
        if not struct_iterator(idaapi.get_struc_name(sid), idaapi.get_struc_size(sid), *additionalArgs):
            break
                        
def foreachFunction(function_iterator, *additionalArgs):
    assertFunction(function_iterator)
    
    begin = getFirstFunction()
    end = getLastFunction()
    
    current_ea = begin
    
    while function_iterator(current_ea, *additionalArgs):
        if not hasNextFunction(current_ea):
            break
        current_ea = getNextFunction(current_ea)

class Selection(object):
    def __init__(self):
        import array
        selection, start_ea, end_ea = idaapi.read_selection()
        #self.selection = selection
        if selection:
            self.start = start_ea
            self.end = end_ea
            arrayType = 'B'
            selsize = self.end - self.start
            
            if selsize >= 256:
                arrayType = 'H' if selsize < 65536 else 'I'
            self.offslist = array.array(arrayType)
            position = self.start
            
            while position < end_ea:
                self.offslist.append(start_ea - position)
                position = nextHead(position)
        else:
            self.start = screenEA()
            self.end = nextHead(self.start)
            self.offslist = None
    def __len__(self):
        return 1 if self.offslist is None else len(self.offslist)
    def __getitem__(self, idx):
        return self.start if self.offslist is None else self.start + self.offslist[idx]
    
def assemble32(line, ea):
    return idaapi.assemble(ea, idc.GetReg(ea, "cs"), ea, True, line)

def getPlainDisasm(ea):
    return idc.GetDisasm(ea)

def addMenuItem(path, name, hotkey, flags, pyfunc, args = None):
    item = idaapi.add_menu_item(path, name, hotkey, flags, pyfunc, args)
    return item is not None

def initDecompiler():
    return idaapi.init_hexrays_plugin()

def nopItem(ea):
    #nops = [0x90] * (nextHead(ea) - ea)
    #idaapi.patch_many_bytes(ea, nops)
    for patch_ea in range(ea, nextHead(ea)):
        idaapi.patch_byte(patch_ea, 0x90)