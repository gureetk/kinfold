# SPDX-License-Identifier: Apache-2.0
"""Wire encoding (PROTOCOL.md section 2) and padding (section 7.4).

All integers are unsigned big-endian. vec16/vec32 are byte strings prefixed
with their length in bytes. Parsers reject truncated input and trailing bytes.
"""
import base64
import re
import struct


class DecodeError(ValueError):
    """Input does not parse. Callers map this to the reason code `malformed`."""


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def vec16(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise ValueError("vec16 longer than 65535 bytes")
    return u16(len(b)) + bytes(b)


def vec32(b: bytes) -> bytes:
    if len(b) > 0xFFFFFFFF:
        raise ValueError("vec32 too long")
    return u32(len(b)) + bytes(b)


_B64U = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u(b: bytes) -> str:
    """base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def unb64u(s: str) -> bytes:
    """Strict base64url decoding: no padding, no other characters, canonical."""
    if not _B64U.match(s) or len(s) % 4 == 1:
        raise DecodeError("bad base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(b) != s:
        raise DecodeError("non-canonical base64url")
    return b


def utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError as e:
        raise DecodeError("bad UTF-8") from e


class Reader:
    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise DecodeError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec32(self) -> bytes:
        return self.take(self.u32())

    def flag(self) -> bool:
        v = self.u8()
        if v > 1:
            raise DecodeError("flag must be 0 or 1")
        return v == 1

    def ids(self, size: int = 16) -> list:
        """vec16 holding a strictly ascending list of fixed-size IDs."""
        blob = self.vec16()
        if len(blob) % size:
            raise DecodeError("ID list length")
        out = [blob[i:i + size] for i in range(0, len(blob), size)]
        if any(out[i] >= out[i + 1] for i in range(len(out) - 1)):
            raise DecodeError("ID list not strictly ascending")
        return out

    def end(self) -> None:
        if self.pos != len(self.data):
            raise DecodeError("trailing bytes")


# --- padding (PROTOCOL.md section 7.4) ---------------------------------------------------

BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 16384, 65536)
MAX_PAYLOAD = 65535


def pad_to(p: bytes, n: int) -> bytes:
    """PadTo(p, n) = p || 0x80 || zero bytes, to exactly n bytes."""
    if len(p) > n - 1:
        raise ValueError("too long to pad")
    return bytes(p) + b"\x80" + bytes(n - len(p) - 1)


def pad(p: bytes) -> bytes:
    """Pad(p) = PadTo(p, the smallest bucket >= len(p) + 1)."""
    if len(p) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    return pad_to(p, next(b for b in BUCKETS if b >= len(p) + 1))


def unpad(x: bytes, sizes=BUCKETS):
    """Returns the unpadded bytes, or None. len(x) must be one of `sizes`."""
    if len(x) not in sizes:
        return None
    y = bytes(x).rstrip(b"\x00")
    if not y or y[-1] != 0x80:
        return None
    return y[:-1]
