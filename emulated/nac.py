import hashlib
from . import mparser as macholibre
from .jelly import Jelly
import plistlib
import logging
logger = logging.getLogger("nac")

BINARY_HASH = "e1181ccad82e6629d52c6a006645ad87ee59bd13"
BINARY_PATH = "emulated/IMDAppleServices"
BINARY_URL = "https://github.com/JJTech0130/nacserver/raw/main/IMDAppleServices"

FAKE_DATA = plistlib.load(open("emulated/data.plist", "rb"))

def load_binary() -> bytes:
    # Open the file at BINARY_PATH, check the hash, and return the binary
    # If the hash doesn't match, raise an exception
    # Download the binary if it doesn't exist
    import os, requests
    if not os.path.exists(BINARY_PATH):
        logger.info("Downloading IMDAppleServices")
        resp = requests.get(BINARY_URL)
        b = resp.content
        # Save the binary
        open(BINARY_PATH, "wb").write(b)
    else:
        logger.debug("Using already downloaded IMDAppleServices")
        b = open(BINARY_PATH, "rb").read()
    if hashlib.sha1(b).hexdigest() != BINARY_HASH:
        raise Exception("Hashes don't match")
    return b


def get_x64_slice(binary: bytes) -> bytes:
    # Get the x64 slice of the binary
    # If there is no x64 slice, raise an exception
    p = macholibre.Parser(binary)
    # Parse the binary to find the x64 slice
    off, size = p.u_get_offset(cpu_type="X86_64")
    return binary[off : off + size]


def nac_init(j: Jelly, cert: bytes):
    # Allocate memory for the cert
    cert_addr = j.malloc(len(cert))
    j.uc.mem_write(cert_addr, cert)

    # Allocate memory for the outputs
    out_validation_ctx_addr = j.malloc(8)
    out_request_bytes_addr = j.malloc(8)
    out_request_len_addr = j.malloc(8)

    # Call the function
    ret = j.instr.call(
        0xB1DB0,
        [
            cert_addr,
            len(cert),
            out_validation_ctx_addr,
            out_request_bytes_addr,
            out_request_len_addr,
        ],
    )

    #print(hex(ret))

    if ret != 0:
        n = ret & 0xffffffff
        n = (n ^ 0x80000000) - 0x80000000
        raise Exception(f"Error calling nac_init: {n}")
    
    # Get the outputs
    validation_ctx_addr = j.uc.mem_read(out_validation_ctx_addr, 8)
    request_bytes_addr = j.uc.mem_read(out_request_bytes_addr, 8)
    request_len = j.uc.mem_read(out_request_len_addr, 8)

    request_bytes_addr = int.from_bytes(request_bytes_addr, 'little')
    request_len = int.from_bytes(request_len, 'little')

    logger.debug(f"Request @ {hex(request_bytes_addr)} : {hex(request_len)}")

    request = j.uc.mem_read(request_bytes_addr, request_len)
    
    validation_ctx_addr = int.from_bytes(validation_ctx_addr, 'little')
    return validation_ctx_addr, request

def nac_key_establishment(j: Jelly, validation_ctx: int, response: bytes):
    response_addr = j.malloc(len(response))
    j.uc.mem_write(response_addr, response)

    ret = j.instr.call(
        0xB1DD0,
        [
            validation_ctx,
            response_addr,
            len(response),
        ],
    )

    if ret != 0:
        n = ret & 0xffffffff
        n = (n ^ 0x80000000) - 0x80000000
        raise Exception(f"Error calling nac_submit: {n}")
    
def nac_sign(j: Jelly, validation_ctx: int):
    #void *validation_ctx, void *unk_bytes, int unk_len,
    #            void **validation_data, int *validation_data_len
    
    out_validation_data_addr = j.malloc(8)
    out_validation_data_len_addr = j.malloc(8)

    ret = j.instr.call(
        0xB1DF0,
        [
            validation_ctx,
            0,
            0,
            out_validation_data_addr,
            out_validation_data_len_addr,
        ],
    )

    if ret != 0:
        n = ret & 0xffffffff
        n = (n ^ 0x80000000) - 0x80000000
        raise Exception(f"Error calling nac_generate: {n}")
    
    validation_data_addr = j.uc.mem_read(out_validation_data_addr, 8)
    validation_data_len = j.uc.mem_read(out_validation_data_len_addr, 8)

    validation_data_addr = int.from_bytes(validation_data_addr, 'little')
    validation_data_len = int.from_bytes(validation_data_len, 'little')

    validation_data = j.uc.mem_read(validation_data_addr, validation_data_len)

    return validation_data


def hook_code(uc, address: int, size: int, user_data):
    logger.debug(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))


def malloc(j: Jelly, len: int) -> int:
    # Hook malloc
    # Return the address of the allocated memory
    #print("malloc hook called with len = %d" % len)
    return j.malloc(len)


def memset_chk(j: Jelly, dest: int, c: int, len: int, destlen: int):
    logger.debug(
        "memset_chk called with dest = 0x%x, c = 0x%x, len = 0x%x, destlen = 0x%x"
        % (dest, c, len, destlen)
    )
    j.uc.mem_write(dest, bytes([c]) * len)
    return 0


def sysctlbyname(j: Jelly):
    return 0  # The output is not checked


def memcpy(j: Jelly, dest: int, src: int, len: int):
    logger.debug("memcpy called with dest = 0x%x, src = 0x%x, len = 0x%x" % (dest, src, len))
    orig = j.uc.mem_read(src, len)
    j.uc.mem_write(dest, bytes(orig))
    return 0

CF_OBJECTS = []

# struct __builtin_CFString {
#     int *isa; // point to __CFConstantStringClassReference
#     int flags;
#     const char *str;
#     long length;
# }
import struct

def _parse_cfstr_ptr(j: Jelly, ptr: int) -> str:
    size = struct.calcsize("<QQQQ")
    data = j.uc.mem_read(ptr, size)
    isa, flags, str_ptr, length = struct.unpack("<QQQQ", data)
    str_data = j.uc.mem_read(str_ptr, length)
    return str_data.decode("utf-8")

def _parse_cstr_ptr(j: Jelly, ptr: int) -> str:
    data = j.uc.mem_read(ptr, 256) # Lazy way to do it
    return data.split(b"\x00")[0].decode("utf-8")

def IORegistryEntryCreateCFProperty(j: Jelly, entry: int, key: int, allocator: int, options: int):
    key_str = _parse_cfstr_ptr(j, key)
    if key_str in FAKE_DATA["iokit"]:
        fake = FAKE_DATA["iokit"][key_str]
        logger.debug(f"IOKit Entry: {key_str} -> {fake}")
        # Return the index of the fake data in CF_OBJECTS
        CF_OBJECTS.append(fake)
        return len(CF_OBJECTS) # NOTE: We will have to subtract 1 from this later, can't return 0 here since that means NULL
    else:
        logger.debug(f"IOKit Entry: {key_str} -> None")
        return 0
        
def CFGetTypeID(j: Jelly, obj: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        return 1
    elif isinstance(obj, str):
        return 2
    else:
        raise Exception("Unknown CF object type")
                                                                                                                      
def CFDataGetLength(j: Jelly, obj: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        return len(obj)
    else:
        raise Exception("Unknown CF object type")
    
def CFDataGetBytes(j: Jelly, obj: int, range_start: int, range_end: int, buf: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        data = obj[range_start:range_end]
        j.uc.mem_write(buf, data)
        logger.debug(f"CFDataGetBytes: {hex(range_start)}-{hex(range_end)} -> {hex(buf)}")
        return len(data)
    else:
        raise Exception("Unknown CF object type")
    
def CFDictionaryCreateMutable(j: Jelly) -> int:
    CF_OBJECTS.append({})
    return len(CF_OBJECTS)

def maybe_object_maybe_string(j: Jelly, obj: int):
    # If it's already a str
    if isinstance(obj, str):
        return obj
    elif obj > len(CF_OBJECTS):
        return obj
        #raise Exception(f"WTF: {hex(obj)}")
        # This is probably a CFString
       # return _parse_cfstr_ptr(j, obj)
    else:
        return CF_OBJECTS[obj - 1]

def CFDictionaryGetValue(j: Jelly, d: int, key: int) -> int:
    logger.debug(f"CFDictionaryGetValue: {d} {hex(key)}")
    d = CF_OBJECTS[d - 1]
    if key == 0xc3c3c3c3c3c3c3c3:
        key = "DADiskDescriptionVolumeUUIDKey" # Weirdness, this is a hack
    key = maybe_object_maybe_string(j, key)
    if isinstance(d, dict):
        if key in d:
            val = d[key]
            logger.debug(f"CFDictionaryGetValue: {key} -> {val}")
            CF_OBJECTS.append(val)
            return len(CF_OBJECTS)
        else:
            raise Exception("Key not found")
            return 0
    else:
        raise Exception("Unknown CF object type")
    
def CFDictionarySetValue(j: Jelly, d: int, key: int, val: int):
    d = CF_OBJECTS[d - 1]
    key = maybe_object_maybe_string(j, key)
    val = maybe_object_maybe_string(j, val)
    if isinstance(d, dict):
        d[key] = val
    else:
        raise Exception("Unknown CF object type")

def DADiskCopyDescription(j: Jelly) -> int:
    description = CFDictionaryCreateMutable(j)
    CFDictionarySetValue(j, description, "DADiskDescriptionVolumeUUIDKey", FAKE_DATA["root_disk_uuid"])
    return description    

def CFStringCreate(j: Jelly, string: str) -> int:
    CF_OBJECTS.append(string)
    return len(CF_OBJECTS)

def CFStringGetLength(j: Jelly, string: int) -> int:
    string = CF_OBJECTS[string - 1]
    if isinstance(string, str):
        return len(string)
    else:
        raise Exception("Unknown CF object type")

def CFStringGetCString(j: Jelly, string: int, buf: int, buf_len: int, encoding: int) -> int:
    string = CF_OBJECTS[string - 1]
    if isinstance(string, str):
        data = string.encode("utf-8")
        j.uc.mem_write(buf, data)
        logger.debug(f"CFStringGetCString: {string} -> {hex(buf)}")
        return len(data)
    else:
        raise Exception("Unknown CF object type")
    
def IOServiceMatching(j: Jelly, name: int) -> int:
    # Read the raw c string pointed to by name
    name = _parse_cstr_ptr(j, name)
    logger.debug(f"IOServiceMatching: {name}")
    # Create a CFString from the name
    name = CFStringCreate(j, name)
    # Create a dictionary
    d = CFDictionaryCreateMutable(j)
    # Set the key "IOProviderClass" to the name
    CFDictionarySetValue(j, d, "IOProviderClass", name)
    # Return the dictionary
    return d
    
def IOServiceGetMatchingService(j: Jelly) -> int:
    return 92

ETH_ITERATOR_HACK = False
def IOServiceGetMatchingServices(j: Jelly, port, match, existing) -> int:
    global ETH_ITERATOR_HACK
    ETH_ITERATOR_HACK = True
    # Write 93 to existing
    j.uc.mem_write(existing, bytes([93]))
    return 0

def IOIteratorNext(j: Jelly, iterator: int) -> int:
    global ETH_ITERATOR_HACK
    if ETH_ITERATOR_HACK:
        ETH_ITERATOR_HACK = False
        return 94
    else:
        return 0
    
def bzero(j: Jelly, ptr: int, len: int):
    j.uc.mem_write(ptr, bytes([0]) * len)
    return 0

def IORegistryEntryGetParentEntry(j: Jelly, entry: int, _, parent: int) -> int:
    j.uc.mem_write(parent, bytes([entry + 100]))
    return 0

import requests, plistlib
def get_cert():
    resp = requests.get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
    resp = plistlib.loads(resp.content)
    return resp["cert"]

def get_session_info(req: bytes) -> bytes:
    body = {
        'session-info-request': req,
    }
    body = plistlib.dumps(body)
    resp = requests.post("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation", data=body, verify=False)
    resp = plistlib.loads(resp.content)
    return resp["session-info"]

def arc4random(j: Jelly) -> int:
    import random
    return random.randint(0, 0xFFFFFFFF)
    #return 0

def load_nac() -> Jelly:
    binary = load_binary()
    binary = get_x64_slice(binary)
    # Create a Jelly object from the binary
    j = Jelly(binary)

    hooks = {
        "_malloc": malloc,
        "___stack_chk_guard": lambda: 0,
        "___memset_chk": memset_chk,
        "_sysctlbyname": lambda _: 0,
        "_memcpy": memcpy,
        "_kIOMasterPortDefault": lambda: 0,
        "_IORegistryEntryFromPath": lambda _: 1,
        "_kCFAllocatorDefault": lambda: 0,
        "_IORegistryEntryCreateCFProperty": IORegistryEntryCreateCFProperty,
        "_CFGetTypeID": CFGetTypeID,
        "_CFStringGetTypeID": lambda _: 2,
        "_CFDataGetTypeID": lambda _: 1,
        "_CFDataGetLength": CFDataGetLength,
        "_CFDataGetBytes": CFDataGetBytes,
        "_CFRelease": lambda _: 0,
        "_IOObjectRelease": lambda _: 0,
        "_statfs$INODE64": lambda _: 0,
        "_DASessionCreate": lambda _: 201,
        "_DADiskCreateFromBSDName": lambda _: 202,
        "_kDADiskDescriptionVolumeUUIDKey": lambda: 0,
        "_DADiskCopyDescription": DADiskCopyDescription,
        "_CFDictionaryGetValue": CFDictionaryGetValue,
        "_CFUUIDCreateString": lambda _, __, uuid: uuid,
        "_CFStringGetLength": CFStringGetLength,
        "_CFStringGetMaximumSizeForEncoding": lambda _, length, __: length,
        "_CFStringGetCString": CFStringGetCString,
        "_free": lambda _: 0,
        "_IOServiceMatching": IOServiceMatching,
        "_IOServiceGetMatchingService": IOServiceGetMatchingService,
        "_CFDictionaryCreateMutable": CFDictionaryCreateMutable,
        "_kCFBooleanTrue": lambda: 0,
        "_CFDictionarySetValue": CFDictionarySetValue,
        "_IOServiceGetMatchingServices": IOServiceGetMatchingServices,
        "_IOIteratorNext": IOIteratorNext,
        "___bzero": bzero,
        "_IORegistryEntryGetParentEntry": IORegistryEntryGetParentEntry,
        "_arc4random": arc4random
    }
    j.setup(hooks)

    return j

def generate_validation_data() -> bytes:
    j = load_nac()
    logger.debug("Loaded NAC library")
    val_ctx, req = nac_init(j,get_cert())
    logger.debug("Initialized NAC")
    session_info = get_session_info(req)
    logger.debug("Got session info")
    nac_key_establishment(j, val_ctx, session_info)
    logger.debug("Submitted session info")
    val_data = nac_sign(j, val_ctx)
    logger.info("Generated validation data")
    return bytes(val_data)

if __name__ == "__main__":
    from base64 import b64encode
    val_data = generate_validation_data()
    logger.info(f"Validation Data: {b64encode(val_data).decode()}")
    #main()