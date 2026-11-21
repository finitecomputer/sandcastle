# One NSM attestation document with the given nonce, printed as base64
# (sandcastle docs/nitro-evidence/pcr0.md). The request is CBOR written by
# hand: {"Attestation": {"nonce": h'..', "user_data": null, "public_key": null}}.
import base64, ctypes, fcntl, os, sys
nonce = bytes.fromhex(sys.argv[1])
assert len(nonce) == 32
def text(s):
    b = s.encode(); assert len(b) < 24; return bytes([0x60 + len(b)]) + b
req = b"\xa1" + text("Attestation") + b"\xa3" + text("nonce") + b"\x58\x20" + nonce + text("user_data") + b"\xf6" + text("public_key") + b"\xf6"
class Iov(ctypes.Structure): _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class Msg(ctypes.Structure): _fields_ = [("req", Iov), ("res", Iov)]
reqbuf = ctypes.create_string_buffer(req, len(req)); resbuf = ctypes.create_string_buffer(0x3000)
m = Msg(Iov(ctypes.addressof(reqbuf), len(req)), Iov(ctypes.addressof(resbuf), 0x3000))
fd = os.open("/dev/nsm", os.O_RDWR)
fcntl.ioctl(fd, 0xC0200A00, m)
res = resbuf.raw[: m.res.len]
i = res.index(b"hdocument") + 9
head = res[i]
if head == 0x59: n, at = int.from_bytes(res[i + 1 : i + 3], "big"), i + 3
elif head == 0x5A: n, at = int.from_bytes(res[i + 1 : i + 5], "big"), i + 5
else: raise SystemExit(f"unexpected CBOR head {head:#x}")
print("DOC " + base64.b64encode(res[at : at + n]).decode(), flush=True)
