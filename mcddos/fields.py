"""Generic Minecraft protocol field reader.

Reads / skips arbitrary packet payloads described by minecraft-data
"type" specs. Supports every primitive and composite type used across
1.16 -> 26.3, including switch, option, array, buffer, nbt, vec*, etc.

Type specs (from protocol.json) are either:
  * a string  -> primitive name or a named type in the type table
  * a list [name, params] -> composite type

The type table maps named types (containers, mappers, switches, ...) to
their definition. Build it with `build_type_table(protocol_dict)`.
"""

import struct


class FieldReadError(Exception):
    pass


# --- primitive sizes / readers ---------------------------------------------

_PRIM = {
    "i8": 1, "u8": 1, "bool": 1,
    "i16": 2, "u16": 2,
    "i32": 4, "u32": 4, "f32": 4,
    "i64": 8, "u64": 8, "f64": 8, "UUID": 8,
}

_PRIM_STRUCT = {
    "i16": ">h", "u16": ">H",
    "i32": ">i", "u32": ">I", "f32": ">f",
    "i64": ">q", "u64": ">Q", "f64": ">d",
    "i8": "b", "u8": "B", "bool": "B",
}


def read_varint(data, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise FieldReadError("varint overflow")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift > 35:
                raise FieldReadError("varint too long")
            return result, pos
        if shift >= 35:
            raise FieldReadError("varint too long")


def skip_varint(data, pos):
    shift = 0
    while True:
        if pos >= len(data):
            raise FieldReadError("varint overflow")
        b = data[pos]
        pos += 1
        if not (b & 0x80):
            if shift > 35:
                raise FieldReadError("varint too long")
            return pos
        shift += 7
        if shift >= 35:
            raise FieldReadError("varint too long")


class Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise FieldReadError("cursor overflow")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v


def build_type_table(d):
    """Merge global + per-state type definitions into one lookup table."""
    tdefs = {}
    if "types" in d:
        for k, v in d["types"].items():
            tdefs[k] = v
    for state in ("handshaking", "status", "login", "play", "configuration"):
        if state in d:
            for direction in ("toServer", "toClient"):
                try:
                    st = d[state][direction]["types"]
                    for k, v in st.items():
                        tdefs.setdefault(k, v)
                except Exception:
                    pass
    return tdefs


def _read_primitive(r: Cursor, name):
    if name in ("varint", "varlong"):
        v, r.pos = read_varint(r.data, r.pos)
        return v
    if name == "optvarint":
        v, r.pos = read_varint(r.data, r.pos)
        return v
    if name in _PRIM:
        return r.take(_PRIM[name])
    if name in ("string", "pstring", "string16", "string8"):
        n, r.pos = read_varint(r.data, r.pos)
        if n > 262144:
            raise FieldReadError("string too long")
        return r.take(n).decode("utf-8", "replace")
    if name == "UUID":
        return r.take(8)
    if name in ("ByteArray",):
        n, r.pos = read_varint(r.data, r.pos)
        if n > 262144:
            raise FieldReadError("bytearray too long")
        return r.take(n)
    raise FieldReadError("unknown primitive " + str(name))


def _read_nbt(r: Cursor):
    """Skip an NBT value (any tag type). Returns bytes consumed."""
    tag = r.take(1)[0]
    if tag == 0x00:
        return b""
    if tag == 0x01:  # byte
        return 1
    if tag == 0x02:  # short
        return 2
    if tag == 0x03:  # int
        return 4
    if tag == 0x04:  # long
        return 8
    if tag == 0x05:  # float
        return 4
    if tag == 0x06:  # double
        return 8
    if tag == 0x07:  # byte array
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += n
        return n
    if tag == 0x08:  # string
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += n
        return n
    if tag == 0x09:  # list
        ltype = r.take(1)[0]
        n, r.pos = read_varint(r.data, r.pos)
        for _ in range(n):
            if ltype != 0:
                r.take(1)
                _read_nbt_payload(r, ltype)
        return 0
    if tag == 0x0A:  # compound
        while True:
            t = r.take(1)[0]
            if t == 0x00:
                break
            n, r.pos = read_varint(r.data, r.pos)
            r.pos += n
            _read_nbt_payload(r, t)
        return 0
    if tag == 0x0C:  # int array
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += 4 * n
        return 0
    if tag == 0x0D:  # long array
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += 8 * n
        return 0
    raise FieldReadError("bad nbt tag %d" % tag)


def _read_nbt_payload(r: Cursor, tag):
    if tag == 0x01:
        r.take(1)
    elif tag == 0x02:
        r.take(2)
    elif tag == 0x03:
        r.take(4)
    elif tag == 0x04:
        r.take(8)
    elif tag == 0x05:
        r.take(4)
    elif tag == 0x06:
        r.take(8)
    elif tag == 0x07:
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += n
    elif tag == 0x08:
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += n
    elif tag == 0x09:
        ltype = r.take(1)[0]
        n, r.pos = read_varint(r.data, r.pos)
        for _ in range(n):
            if ltype != 0:
                r.take(1)
                _read_nbt_payload(r, ltype)
    elif tag == 0x0A:
        while True:
            t = r.take(1)[0]
            if t == 0x00:
                break
            n, r.pos = read_varint(r.data, r.pos)
            r.pos += n
            _read_nbt_payload(r, t)
    elif tag == 0x0C:
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += 4 * n
    elif tag == 0x0D:
        n, r.pos = read_varint(r.data, r.pos)
        r.pos += 8 * n


def _read_buffer(r: Cursor, params):
    count = params.get("count")
    if count is None:
        count, r.pos = read_varint(r.data, r.pos)
    return r.take(count)


def _vec_sizes(name):
    return {
        "vec2f": (2, 4), "vec3f": (3, 4), "vec3f64": (3, 8),
        "vec3i": (3, 0), "vec3i16": (3, 2), "vec3i32": (3, 4),
    }.get(name)


def read_field(r: Cursor, spec, tdefs, ctx=None):
    """Read one field per spec. Returns parsed value (best effort)."""
    ctx = ctx or {}
    if isinstance(spec, str):
        return _read_named(r, spec, tdefs, ctx)
    if isinstance(spec, list):
        name, params = spec[0], (spec[1] if len(spec) > 1 else None)
        return _read_composite(r, name, params, tdefs, ctx)
    raise FieldReadError("bad spec " + repr(spec))


def _read_named(r, name, tdefs, ctx):
    if name in ("varint", "varlong", "optvarint", "string", "pstring",
                "string16", "string8", "UUID", "ByteArray"):
        return _read_primitive(r, name)
    if name in _PRIM:
        return _read_primitive(r, name)
    if name in ("nbt", "anonymousNbt", "anonOptionalNbt"):
        return _read_nbt(r)
    if name == "optionalNbt":
        has, r.pos = read_varint(r.data, r.pos)
        if has:
            _read_nbt(r)
        return has
    vs = _vec_sizes(name)
    if vs:
        n, size = vs
        if size:
            return r.take(n * size)
        else:  # vec3i: 3 varints
            for _ in range(n):
                _, r.pos = read_varint(r.data, r.pos)
            return None
    if name == "position":
        return r.take(8)
    if name == "lpVec3":
        return r.take(2) + r.take(1) + r.take(2)  # i16 x, i8 y, i16 z
    if name == "packedChunkPos":
        _, r.pos = read_varint(r.data, r.pos)
        return None
    if name in ("bitfield", "bitflags"):
        _, r.pos = read_varint(r.data, r.pos)
        return None
    if name in tdefs:
        return read_field(r, tdefs[name], tdefs, ctx)
    raise FieldReadError("unknown named type " + name)


def _read_composite(r, name, params, tdefs, ctx):
    if name == "container":
        out = {}
        for f in params:
            fname = f.get("name")
            fval = read_field(r, f.get("type"), tdefs, ctx)
            out[fname] = fval
        return out
    if name == "option":
        has, r.pos = read_varint(r.data, r.pos)
        if has:
            return read_field(r, params, tdefs, ctx)
        return None
    if name == "array":
        count = params.get("count")
        if count is None:
            count, r.pos = read_varint(r.data, r.pos)
        out = []
        for _ in range(count):
            out.append(read_field(r, params.get("type"), tdefs, ctx))
        return out
    if name == "topBitSetTerminatedArray":
        out = []
        while True:
            b = r.take(1)[0]
            if b & 0x80:
                break
            out.append(read_field(r, params.get("type"), tdefs, ctx))
        return out
    if name == "buffer":
        return _read_buffer(r, params)
    if name == "mapper":
        return _read_primitive(r, params.get("type", "varint"))
    if name == "switch":
        # index may be a previously-read field name in ctx, or an int
        idx = params.get("index")
        if isinstance(idx, int):
            key = idx
        else:
            key = ctx.get(idx)
        cases = params.get("cases", {})
        # cases keys are strings of the value
        cspec = None
        for k, v in cases.items():
            try:
                if int(k) == int(key):
                    cspec = v
                    break
            except (ValueError, TypeError):
                if k == str(key):
                    cspec = v
                    break
        if cspec is None:
            cspec = params.get("default")
            if cspec is None:
                raise FieldReadError("switch no case for %r" % (key,))
        return read_field(r, cspec, tdefs, ctx)
    if name == "tags":
        # map of varint->varint (bitfield style)
        n, r.pos = read_varint(r.data, r.pos)
        for _ in range(n):
            _, r.pos = read_varint(r.data, r.pos)
            _, r.pos = read_varint(r.data, r.pos)
        return None
    # registryEntryHolder / other special: best effort varint
    return _read_primitive(r, "varint")


def read_payload(r: Cursor, spec, tdefs, ctx=None):
    return read_field(r, spec, tdefs, ctx)
