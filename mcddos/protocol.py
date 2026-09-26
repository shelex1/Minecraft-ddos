"""Minecraft Java Edition network protocol primitives (1.16 -> 26.3)."""
import json
import socket
import struct


class MCReadError(Exception):
    pass


class Reader:
    """Reader for MC packet payloads (post-framing). Handles bundled
    messages (1.20.2+ / 764+) transparently."""

    def __init__(self, data: bytes, protocol: int):
        self.data = data
        self.pos = 0
        self.protocol = protocol
        self.bundles = []  # list of bytes payloads for bundled packets

    def read_varint(self) -> int:
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise MCReadError("varint overflow")
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if shift > 35:
                    raise MCReadError("varint too long")
                return result
            if shift >= 35:
                raise MCReadError("varint too long")

    def read_varlong(self):
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise MCReadError("varlong overflow")
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                return result

    def read_i64(self) -> int:
        v = self.read_bytes(8)
        return struct.unpack(">q", v)[0]

    def read_i32(self) -> int:
        v = self.read_bytes(4)
        return struct.unpack(">i", v)[0]

    def read_i16(self) -> int:
        v = self.read_bytes(2)
        return struct.unpack(">h", v)[0]

    def read_bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise MCReadError("bytes overflow")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def read_string(self) -> str:
        n = self.read_varint()
        if n > 32768:
            raise MCReadError("string too long")
        return self.read_bytes(n).decode("utf-8", "replace")


def _varint_len(v: int) -> int:
    n = 1
    while v & ~0x7F:
        v >>= 7
        n += 1
    return n


def varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def varlong(v: int) -> bytes:
    return varint(v)


def i64(v: int) -> bytes:
    return struct.pack(">q", v)


def i32(v: int) -> bytes:
    return struct.pack(">i", v)


def str_field(s: str) -> bytes:
    b = s.encode("utf-8")
    return varint(len(b)) + b


def uuid_field(b: bytes) -> bytes:
    return b[:16]


def encode_field(ftype, value, tdefs=None):
    """Encode a single protocol field.

    ftype: 'string'|'varint'|'i64'|'i32'|'u8'|'i8'|'bool'|'UUID'|
           ['option', inner] | ['buffer', {countType|count}] |
           ['mapper', {...}] | ['array', {countType, type}] |
           'previousMessages' | ... (named via tdefs)
    value: Python value matching the field.
    """
    if ftype == "string":
        return str_field(value)
    if ftype == "varint":
        return varint(value)
    if ftype == "i64":
        return i64(value)
    if ftype == "i32":
        return i32(value)
    if ftype == "u8":
        return bytes([value & 0xFF])
    if ftype == "i8":
        return bytes([value & 0xFF])
    if ftype == "bool":
        return b"\x01" if value else b"\x00"
    if ftype == "UUID":
        return uuid_field(value)
    if ftype == "previousMessages":
        # array of {messageSender:UUID, messageSignature:buffer[varint]}
        return varint(0)  # empty array
    if isinstance(ftype, list) and ftype:
        kind = ftype[0]
        if kind == "option":
            inner = ftype[1]
            if value is None:
                return b"\x00"
            return b"\x01" + encode_field(inner, value, tdefs)
        if kind == "buffer":
            params = ftype[1] if len(ftype) > 1 else {}
            raw = value if isinstance(value, bytes) else b""
            if "count" in params:
                n = params["count"]
                if len(raw) < n:
                    raw = raw + b"\x00" * (n - len(raw))
                return raw[:n]
            # countType varint
            return varint(len(raw)) + raw
        if kind == "mapper":
            return varint(value)
        if kind == "array":
            params = ftype[1] if len(ftype) > 1 else {}
            if isinstance(value, list):
                body = b"".join(encode_field(params.get("type"), v, tdefs) for v in value)
                ct = params.get("countType", "varint")
                if ct == "varint":
                    return varint(len(value)) + body
                return body
            return b""
        if kind == "container":
            # value is list of (name, type, val) already encoded? treat value as list of values
            fields = ftype[1]
            body = b""
            vals = value if isinstance(value, list) else []
            for i, f in enumerate(fields):
                body += encode_field(f.get("type"), vals[i] if i < len(vals) else None, tdefs)
            return body
    # named type via tdefs
    if tdefs and ftype in tdefs:
        return encode_field(tdefs[ftype], value, tdefs)
    # fallback
    return varint(value)


def handshake_payload(protocol: int, ip: str, port: int, next_state: int) -> bytes:
    return varint(protocol) + str_field(ip) + struct.pack(">H", port) + varint(next_state)


def handshake_packet(protocol: int, ip: str, port: int, next_state: int) -> bytes:
    payload = handshake_payload(protocol, ip, port, next_state)
    # frame length covers packet-id byte + payload
    return varint(len(payload) + 1) + varint(0x00) + payload


def status_request_packet() -> bytes:
    """Full framed status request: packet id 0x00 in a 1-byte frame."""
    body = varint(0x00)
    return varint(len(body)) + body


def status_response(data: bytes) -> dict:
    """Parse 1.16+ status response: packet body is a JSON string directly."""
    r = Reader(data, 0)
    # 1.16+ status response: packet id (0x00) then JSON string
    try:
        r.read_varint()
        j = r.read_string()
        return json.loads(j)
    except Exception:
        return {}
    try:
        t = r.read_varint()
    except MCReadError:
        return {}
    if t == 1:
        try:
            j = r.read_string()
            try:
                return json.loads(j)
            except Exception:
                return {"raw": j}
        except MCReadError:
            return {}
    # legacy
    try:
        r2 = Reader(data, 0)
        version = r2.read_string()
        try:
            return json.loads(version)
        except Exception:
            return {"raw": version}
    except MCReadError:
        return {}


async def read_exact_async(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = await sock.recv(min(8192, n - len(buf)))
        if not chunk:
            raise MCReadError("connection closed while reading")
        buf += chunk
    return buf


async def read_frame_async(sock):
    """Read one MC framed packet. Returns payload bytes (incl. inner packet id)."""
    length = 0
    shift = 0
    while True:
        b = await read_exact_async(sock, 1)[0]
        length |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift > 35:
            raise MCReadError("bad length")
    if length <= 0:
        return b""
    return await read_exact_async(sock, length)


def connect_sync(host, port, timeout=10.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise MCReadError("closed")
        buf += chunk
    return buf


def read_frame_sync(sock) -> bytes:
    length = 0
    shift = 0
    while True:
        b = recv_exact(sock, 1)[0]
        length |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    if length <= 0:
        return b""
    return recv_exact(sock, length)


def parse_status(payload: bytes) -> dict:
    """Parse the payload of a status response (after frame reading)."""
    return status_response(payload)
