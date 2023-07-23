from io import BytesIO
import unicorn
from . import mparser as macholibre
import logging
logger = logging.getLogger("jelly")

STOP_ADDRESS = 0x00900000 # Used as a return address when calling functions

ARG_REGISTERS = [
    unicorn.x86_const.UC_X86_REG_RDI,
    unicorn.x86_const.UC_X86_REG_RSI,
    unicorn.x86_const.UC_X86_REG_RDX,
    unicorn.x86_const.UC_X86_REG_RCX,
    unicorn.x86_const.UC_X86_REG_R8,
    unicorn.x86_const.UC_X86_REG_R9
]

class VirtualInstructions:
    def __init__(self, uc: unicorn.Uc):
        self.uc = uc

    def push(self, value: int):
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP) - 8)
        self.uc.mem_write(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP), value.to_bytes(8, byteorder='little'))

    def pop(self) -> int:
        value = int.from_bytes(self.uc.mem_read(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP), 8), byteorder='little')
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP) + 8)
        return value
    
    def _set_args(self, args: list[int]):
        for i in range(len(args)):
            if i < 6:
                self.uc.reg_write(ARG_REGISTERS[i], args[i])
            else:
                self.push(args[i])

    
    def call(self, address: int, args: list[int] = []):
        logger.debug(f"Calling {hex(address)} with args {args}")
        self.push(STOP_ADDRESS)
        self._set_args(args)
        self.uc.emu_start(address, STOP_ADDRESS)
        return self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX)

        
class Jelly:
    # Constants
    UC_ARCH = unicorn.UC_ARCH_X86
    UC_MODE = unicorn.UC_MODE_64

    BINARY_BASE = 0x0

    HOOK_BASE = 0xD00000
    HOOK_SIZE = 0x1000

    STACK_BASE = 0x00300000
    STACK_SIZE = 0x00100000

    HEAP_BASE = 0x00400000
    HEAP_SIZE = 0x00100000

    STOP_ADDRESS = 0x00900000

    # Public variables
    _hooks: dict[str, callable] = {}
    """Symbol name to hook function mapping"""

    instr: VirtualInstructions = None

    uc: unicorn.Uc = None
    
    # Private variables
    _binary: bytes = b""

    _heap_use: int = 0

    def __init__(self, binary: bytes):
        self._binary = binary

    def setup(self, hooks: dict[str, callable] = {}):
        self._hooks = hooks
        self._setup_unicorn()
        self.instr = VirtualInstructions(self.uc)
        self._setup_hooks()
        self._map_binary()
        self._setup_stack()
        self._setup_heap()
        self._setup_stop()


    def _setup_unicorn(self):
        self.uc = unicorn.Uc(self.UC_ARCH, self.UC_MODE)

    def _setup_stack(self):   
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self.uc.mem_write(self.STACK_BASE, b"\x00" * self.STACK_SIZE)
        
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self.STACK_BASE + self.STACK_SIZE)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_EBP, self.STACK_BASE + self.STACK_SIZE)

    def _setup_heap(self):
        self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)
        self.uc.mem_write(self.HEAP_BASE, b"\x00" * self.HEAP_SIZE)

    def debug_registers(self):
        logger.debug(f"""
        RAX: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX))}
        RBX: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX))}
        RCX: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX))}
        RDX: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX))}
        RSI: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI))}
        RDI: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RDI))}
        RSP: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP))}
        RBP: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP))}
        RIP: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP))}
        R8: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_R8))}
        R9: {hex(self.uc.reg_read(unicorn.x86_const.UC_X86_REG_R9))}
              """)
    def wrap_hook(self, func: callable) -> callable:
        # Get the number of arguments the function takes
        arg_count = func.__code__.co_argcount
        #print(f"Wrapping {arg_count} argument function {func.__name__}")
        # Create a wrapper function that reads the arguments from registers and the stack
        def wrapper(self: 'Jelly'):
            args = []
            for i in range(1, arg_count):
                if i < 6:
                    args.append(self.uc.reg_read(ARG_REGISTERS[i-1]))
                else:
                    args.append(self.instr.pop())
            #print(ARG_REGISTERS[1])
            #self.debug_registers()
            logger.debug(f"calling {func.__name__}")
            if args != []:
                logger.debug(f" with args: {args}")
            ret = func(self, *args)
            if ret is not None:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, ret)
            return
        return wrapper


    def malloc(self, size: int) -> int:
        # Very naive malloc implementation
        addr = self.HEAP_BASE + self._heap_use
        self._heap_use += size
        return addr

    def _setup_stop(self):
        self.uc.mem_map(self.STOP_ADDRESS, 0x1000)
        self.uc.mem_write(self.STOP_ADDRESS, b"\xc3" * 0x1000)

    def _resolve_hook(uc: unicorn.Uc, address: int, size: int, self: 'Jelly'):
        for name, addr in self._resolved_hooks.items():
            if addr == address:
                logger.debug(f"{name}: ")
                self._hooks[name](self)
    
    def _setup_hooks(self):
        # Wrap all hooks
        for name, func in self._hooks.items():
            self._hooks[name] = self.wrap_hook(func)
        
        self.uc.mem_map(self.HOOK_BASE, self.HOOK_SIZE)
        # Write 'ret' instruction to all hook addresses
        self.uc.mem_write(self.HOOK_BASE, b"\xc3" * self.HOOK_SIZE)
        # Assign address in hook space to each hook
        current_address = self.HOOK_BASE
        self._resolved_hooks = {}
        for hook in self._hooks:
            self._resolved_hooks[hook] = current_address
            current_address += 1
        # Add unicorn instruction hook to entire hook space
        self.uc.hook_add(unicorn.UC_HOOK_CODE, Jelly._resolve_hook, begin=self.HOOK_BASE, end=self.HOOK_BASE + self.HOOK_SIZE, user_data=self)

    def _map_binary(self):
        self.uc.mem_map(self.BINARY_BASE, round_to_page_size(len(self._binary), self.uc.ctl_get_page_size()))
        self.uc.mem_write(self.BINARY_BASE, self._binary)

        # Unmap the first page so we can catch NULL derefs
        self.uc.mem_unmap(0x0, self.uc.ctl_get_page_size())

        # Parse the binary so we can process binds
        p = macholibre.Parser(self._binary)
        p.parse()
        
        for seg in p.segments:
            for section in seg['sects']:
                if section['type'] == 'LAZY_SYMBOL_POINTERS' or section['type'] == 'NON_LAZY_SYMBOL_POINTERS':
                    self._parse_lazy_binds(self.uc, section['r1'], section, self._binary[p.dysymtab['indirectsymoff']:], self._binary[p.symtab['stroff']:], self._binary[p.symtab['symoff']:])

        self._parse_binds(self.uc, self._binary[p.dyld_info['bind_off']:p.dyld_info['bind_off']+p.dyld_info['bind_size']], p.segments)

    def _do_bind(self, mu: unicorn.Uc, type, location, name):
        if type == 1: # BIND_TYPE_POINTER
            if name in self._hooks:
                #print(f"Hooking {name} at {hex(location)}")
                mu.mem_write(location, self._resolved_hooks[name].to_bytes(8, byteorder='little'))
            else:
                #print(f"Unknown symbol {name}")
                pass
        else:
            raise NotImplementedError(f"Unknown bind type {type}")
        
    def _parse_lazy_binds(self, mu: unicorn.Uc, indirect_offset, section, dysimtab, strtab, symtab):
        logger.debug(f"Doing binds for {section['name']}")
        for i in range(0, int(section['size']/8)):     
            # Parse into proper list?   
            dysym = dysimtab[(indirect_offset + i)*4:(indirect_offset + i)*4+4]
            dysym = int.from_bytes(dysym, 'little')
            index = dysym & 0x3fffffff

            # Proper list too?
            symbol = symtab[index * 16:(index * 16) + 4]
            strx = int.from_bytes(symbol, 'little')

            name = c_string(strtab, strx) # Remove _ at beginning
            #print(f"Lazy bind for {hex(section['offset'] + (i * 8))} : {name}")
            self._do_bind(mu, 1, section['offset'] + (i * 8), name)
    
    def _parse_binds(self, mu: unicorn.Uc, binds: bytes, segments):
        blen = len(binds)
        binds: BytesIO = BytesIO(binds)

        ordinal = 0
        symbolName = ''
        type = BIND_TYPE_POINTER
        addend = 0
        segIndex = 0
        segOffset = 0

        while binds.tell() < blen:
            current = binds.read(1)[0]
            opcode = current & BIND_OPCODE_MASK
            immediate = current & BIND_IMMEDIATE_MASK

            #print(f"{hex(offset)}: {hex(opcode)} {hex(immediate)}")

            if opcode == BIND_OPCODE_DONE:
                logger.debug("BIND_OPCODE_DONE")
                break
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = immediate   
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                #ordinal = uLEB128(&p);
                ordinal = decodeULEB128(binds)
                #raise NotImplementedError("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB")
            elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                if (immediate == 0):
                    ordinal = 0
                else:
                    ordinal = BIND_OPCODE_MASK | immediate
            elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                # Parse string until null terminator
                symbolName = ''
                while True:
                    b = binds.read(1)[0]
                    if b == 0:
                        break
                    symbolName += chr(b)
                #while binds[offset] != 0:
                #    symbolName += chr(binds[offset])
                #    offset += 1
                #offset += 1
                #print(f"Symbol name: {symbolName}")
            elif opcode == BIND_OPCODE_SET_TYPE_IMM:
                type = immediate
            elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
                #addend = sLEB128(&p);
                raise NotImplementedError("BIND_OPCODE_SET_ADDEND_SLEB")
            elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex = immediate
                segOffset = decodeULEB128(binds)
                #raise NotImplementedError("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB")
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += decodeULEB128(binds)
                #segOffset += uLEB128(&p);
                #raise NotImplementedError("BIND_OPCODE_ADD_ADDR_ULEB")
            elif opcode == BIND_OPCODE_DO_BIND:
                self._do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
                segOffset += 8
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                self._do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
                segOffset += decodeULEB128(binds) + 8
                #bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
                #segOffset += uLEB128(&p) + size_t.sizeof;
                #raise NotImplementedError("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB")
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                #bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
                self._do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
                segOffset += immediate * 8 + 8
            elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count = decodeULEB128(binds)
                skip = decodeULEB128(binds)
                for i in range(count):
                    self._do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
                    segOffset += skip + 8
                # uint64_t count = uLEB128(&p);
                # uint64_t skip = uLEB128(&p);
                # for (uint64_t i = 0; i < count; i++) {
                #     bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
                #     segOffset += skip + size_t.sizeof;
                # }
                #raise NotImplementedError("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB")
            else:
                logger.error(f"Unknown bind opcode {opcode}")

# Mach-O defines
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
BIND_OPCODE_THREADED = 0xD0

BIND_TYPE_POINTER = 1

BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F

# Helper functions
def round_to_page_size(size: int, page_size: int) -> int:
    return (size + page_size - 1) & ~(page_size - 1)

def decodeULEB128(bytes: BytesIO) -> int:
    result = 0
    shift = 0
    while True:
        b = bytes.read(1)[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result

def c_string(bytes, start: int = 0) -> str:
    out = ''
    i = start
    
    while True:
        if i > len(bytes) or bytes[i] == 0:
            break
        out += chr(bytes[i])
        #print(start)
        #print(chr(bytes[i]))
        i += 1
    return out