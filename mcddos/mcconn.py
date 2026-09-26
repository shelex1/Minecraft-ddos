"""Async Minecraft connection core: handshake -> status -> login -> play.

Handles per-version packet IDs (from data/packets.json), compression
thresholds, and bundled messages (1.20.2+). Works against vanilla,
Velocity and BungeeCord backends. Offline (cracked) mode by default.
"""
import asyncio
import json
import os
import struct
import time
import zlib

from . import protocol as mc
from .fields import Cursor, build_type_table, read_varint, FieldReadError
from .versions import protocol_of, guess_version_for_protocol

_DATA = os.path.join(os.path.dirname(__file__), "data", "packets.json")
with open(_DATA) as _f:
    _PKTS = json.load(_f)

# optional full protocol.json for generic field parsing (login_start fields etc.)
_FULL = {}
_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def pkt_info(pvn):
    return _PKTS.get(str(pvn), {})


def _kick_cleanness(s):
    """Fraction of printable ASCII chars (0x20-0x7e)."""
    if not s:
        return 0.0
    ok = sum(1 for ch in s if 0x20 <= ord(ch) <= 0x7e)
    return ok / len(s)


def _longest_printable(data):
    best, cur = "", ""
    for b in data:
        if 0x20 <= b <= 0x7e:
            cur += chr(b)
        else:
            if len(cur) > len(best):
                best = cur
            cur = ""
    if len(cur) > len(best):
        best = cur
    return best


def _extract_kick(payload, pvn):
    """Extract human kick text (legacy string / JSON / NBT chat component)."""
    if not payload:
        return None
    # A) JSON string component (pre-1.20.2): cleanest
    try:
        j = json.loads(payload.decode("utf-8", "replace"))
        if isinstance(j, dict):
            v = j.get("text") or j.get("reason") or j.get("extra")
            if isinstance(v, str) and v.strip():
                return v
            if isinstance(v, list):
                t = " ".join(x.get("text", "") if isinstance(x, dict) else str(x) for x in v)
                if t.strip():
                    return t
        elif isinstance(j, str) and j.strip():
            return j
    except Exception:
        pass
    # B) legacy plain string (1.16-1.19.3): only if clean printable
    try:
        r = mc.Reader(payload, pvn)
        s = r.read_string()
        if s and s.strip() and _kick_cleanness(s) >= 0.9:
            return s
    except Exception:
        pass
    # C) NBT chat component (1.20.2+): longest printable run (>=8 chars)
    best = _longest_printable(payload)
    if len(best) >= 8:
        return best.lstrip('+-: ') or None
    return None


class MCConnError(Exception):
    pass


class MCConn:
    """One Minecraft server connection.

    Usage:
        c = MCConn(host, port)
        await c.status()          # quick ping (no login)
        await c.login(version)    # full login to play state
        await c.chat("hello")
        await c.close()
    """

    def __init__(self, host, port=25565, timeout=10.0, proxy=None,
                 username="ddoser", online=False, seed=None, log=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.proxy = proxy  # dict from proxies.parse_proxy_line or None
        self.username = username
        self.online = online
        self.seed = seed or os.urandom(32)
        self.log = log or (lambda *a: None)
        self.pvn = None
        self.protocol = None
        self.state = "none"  # none/status/login/configuration/play
        self.compression = None
        self.kick_reason = None
        self.real_backend = None  # (ip, port, kind) from prelogin
        self._reader = None
        self._writer = None
        self._closed = False
        self._zlib = zlib.decompressobj()
        self._bundle_buf = []  # queued bundled sub-packets
        self._join_game = None
        self._keepalive_counter = 0

    # ---- low level io -----------------------------------------------------
    async def _open(self):
        if self.proxy:
            s = await self._open_proxy()
            self._reader, self._writer = s
        else:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self.timeout)
        import socket as _s
        sock = self._writer.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_NODELAY, 1)
            except Exception:
                pass
        self.state = "connected"

    async def _open_proxy(self):
        import asyncio
        p = self.proxy
        host, port = self.host, self.port
        if p["type"] in ("http", "https"):
            r, w = await asyncio.wait_for(asyncio.open_connection(p["host"], p["port"]), self.timeout)
            buf = b"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host.encode(), port, host.encode(), port)
            if p.get("userpass"):
                import base64
                buf += b"Proxy-Authorization: Basic " + base64.b64encode(p["userpass"].encode()) + b"\r\n"
            buf += b"\r\n"
            w.write(buf)
            await w.drain()
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = await asyncio.wait_for(r.read(1024), self.timeout)
                if not chunk:
                    raise MCConnError("proxy closed")
                resp += chunk
            if b" 200" not in resp.split(b"\r\n")[0]:
                raise MCConnError("proxy no 200")
            return r, w
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(p["host"], p["port"]), self.timeout)
            if p["type"] in ("socks4", "socks4a"):
                w.write(b"\x04\x01" + struct.pack(">H", port) +
                        socket_inet_aton(host) + b"\x00")
                await w.drain()
                resp = await asyncio.wait_for(r.read(8), self.timeout)
                if len(resp) < 4 or resp[1] != 0:
                    raise MCConnError("socks4 failed")
            else:  # socks5 / socks5h
                w.write(b"\x05\x01\x00")
                await w.drain()
                resp = await asyncio.wait_for(r.read(2), self.timeout)
                if len(resp) < 2 or resp[0] != 5 or resp[1] == 0xFF:
                    raise MCConnError("socks5 failed")
                if p.get("userpass"):
                    up = p["userpass"].split(":", 1)
                    u = (up[1] if len(up) > 1 else "").encode()
                    w.write(b"\x05\x02" + bytes([len(u)]) + u)
                    await w.drain()
                    resp = await asyncio.wait_for(r.read(2), self.timeout)
                    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                        raise MCConnError("socks5 auth failed")
                hb = host.encode()
                if p["type"] == "socks5h":
                    w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
                else:
                    w.write(b"\x05\x01\x00\x01" + socket_inet_aton(host) + struct.pack(">H", port))
                await w.drain()
                resp = await asyncio.wait_for(r.read(4), self.timeout)
                if len(resp) < 4 or resp[1] != 0:
                    raise MCConnError("socks5 connect failed")
            return r, w

    async def _send_raw(self, payload: bytes):
        if self._closed:
            return
        self._writer.write(payload)
        await self._writer.drain()

    async def _send_packet(self, payload: bytes):
        """Send one framed packet (with compression if active).

        Compression format: frame = [varint len][inner];
        inner = [varint uncompressedLen][raw-or-deflated].
        uncompressedLen == 0 means raw bytes follow.
        """
        if self.compression is not None:
            if self.compression > 0 and len(payload) >= self.compression:
                comp = zlib.compress(payload)
                inner = mc.varint(len(payload)) + comp
            else:
                inner = mc.varint(0) + payload
        else:
            inner = payload
        await self._send_raw(mc.varint(len(inner)) + inner)

    async def _read_varint_raw(self):
        result = 0
        shift = 0
        while True:
            b = await self._read_exact(1)
            if not b:
                raise MCConnError("closed during varint")
            byte = b[0]
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                if shift > 35:
                    raise MCConnError("varint too long")
                return result
            if shift >= 35:
                raise MCConnError("varint too long")

    async def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = await asyncio.wait_for(self._reader.read(min(65536, n - len(buf))), self.timeout)
            if not chunk:
                raise MCConnError("connection closed")
            buf += chunk
        return buf

    async def _read_frame(self):
        """Read one framed packet, return inner payload (bytes, no packet id split)."""
        length = await self._read_varint_raw()
        if length <= 0:
            return b""
        data = await self._read_exact(length)
        if self.compression is not None and length > 0:
            ulen, pos = read_varint(data, 0)
            if ulen == 0:
                data = data[pos:]
            else:
                data = self._zlib.decompress(data[pos:])
        return data

    async def _read_packet(self):
        """Read one logical packet. Handles bundled messages (1.20.2+).
        Returns (packet_id, payload_after_id)."""
        # consume any queued bundled sub-packets first
        if self._bundle_buf:
            sid, payload = self._bundle_buf.pop(0)
            # note: pstart is into the ORIGINAL frame data; but we only kept ids.
            # store payload slices instead.
            return sid, payload
        data = await self._read_frame()
        if not data:
            return None, b""
        # packet id
        pid, pos = read_varint(data, 0)
        # bundle delimiter? (1.20.2+ id 0)
        if pid == 0 and self.pvn is not None and pkt_info(self.pvn).get("bundle") == 0:
            # bundle: series of [varint subLen][varint subId][payload]
            cur = pos
            first = True
            first_sid = None
            first_payload = None
            while cur < len(data):
                slen, id_start = read_varint(data, cur)  # subLen (covers id+payload)
                sid, pstart = read_varint(data, id_start)
                idlen = pstart - id_start
                payload_end = id_start + slen
                payload = data[pstart:payload_end]
                if first:
                    first_sid = sid
                    first_payload = payload
                    first = False
                else:
                    self._bundle_buf.append((sid, payload))
                cur = payload_end
            return first_sid, first_payload
        return pid, data[pos:]

    # ---- protocol phases --------------------------------------------------
    async def status(self, pvn=None):
        """Quick status ping. Returns status dict or None. Sets self.pvn."""
        if pvn is None:
            pvn = 767
        pvn = protocol_of(pvn) if not isinstance(pvn, int) else pvn
        self.pvn = pvn
        await self._open()
        try:
            hs = mc.handshake_payload(pvn, self.host, self.port, 1)
            await self._send_raw(mc.varint(len(hs) + 1) + mc.varint(0) + hs)
            await self._send_raw(mc.status_request_packet())
            data = await self._read_frame()
            info = mc.parse_status(data)
            return info
        finally:
            if self.state == "connected":
                await self._close_raw()

    async def _close_raw(self):
        if not self._closed:
            self._closed = True
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

    async def close(self):
        await self._close_raw()

    def _login_start_payload(self):
        info = pkt_info(self.pvn)
        fields = info.get("login_start_fields") or [["username", "string"]]
        payload = mc.varint(0) + mc.str_field(self.username)
        for name, ftype in fields:
            if name == "username":
                continue
            if name == "signature":
                # no signed chat key: option absent
                payload += b"\x00"
            elif name == "playerUUID":
                is_opt = isinstance(ftype, list) and ftype[0] == "option"
                uuidb = b"\x00" * 16
                if is_opt:
                    payload += b"\x00"  # absent (offline)
                else:
                    payload += uuidb
        return payload

    def _handle_prelogin(self, channel, data):
        """Parse bungee/velocity prelogin to find backend."""
        if channel == "bungeecord:pre_login":
            try:
                r = mc.Reader(data, 0)
                ip = r.read_varint()
                port = r.read_varint()
                if 0 < ip <= 0xFFFFFFFF:
                    self.real_backend = (".".join(str((ip >> s) & 0xFF) for s in (24, 16, 8, 0)), port, "bungeecord")
            except Exception:
                pass
            return True
        if channel in ("velocity:pre_login",) or "pre_login" in channel:
            try:
                j = json.loads(data.decode("utf-8", "replace"))
                if isinstance(j, list) and j:
                    e = j[0]
                    host = e.get("host") or e.get("address")
                    port = e.get("port", 25565)
                    if host:
                        self.real_backend = (host, int(port), "velocity")
            except Exception:
                pass
            return True
        return False

    async def login(self, version, wait_play=True, timeout=None):
        """Full login. version like '1.19', '1.20.4' or protocol int.
        Reaches play state (or configuration for 1.20+). Returns True on success."""
        self.pvn = protocol_of(version) if not isinstance(version, int) else version
        if timeout:
            self.timeout = timeout
        info = pkt_info(self.pvn)
        self._login_success = info.get("login_success", 2)
        self._login_compress = info.get("login_compress", 3)
        self._login_disconnect = info.get("login_disconnect", 0)
        self._login_plugin_req = info.get("login_plugin_req", 4)
        self._login_enc = info.get("login_enc", 1)
        self._login_plugin_resp = info.get("login_plugin_resp", 2)
        self._login_ack = info.get("login_ack")  # >=764
        self._keep_alive_c2s = info.get("keep_alive_c2s")
        self._keep_alive_s2c = info.get("keep_alive_s2c")
        self._play_disconnect = info.get("play_disconnect")
        self._has_config = info.get("has_config", False)

        await self._open()
        try:
            # handshake -> login
            hs = mc.handshake_payload(self.pvn, self.host, self.port, 2)
            await self._send_raw(mc.varint(len(hs) + 1) + mc.varint(0) + hs)
            # login_start
            await self._send_packet(self._login_start_payload())

            self.state = "login"
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                pid, payload = await self._read_packet()
                if pid is None:
                    return True  # clean close after success
                if pid == self._login_plugin_req:
                    r = mc.Reader(payload, self.pvn)
                    try:
                        msg_id = r.read_varint()
                        channel = r.read_string()
                        rest = payload[r.pos:]
                    except Exception:
                        msg_id, channel, rest = 0, "", b""
                    is_pre = self._handle_prelogin(channel, rest)
                    # respond: 1 = success (handled), 0 = ignore/fail
                    resp_data = mc.varint(msg_id) + mc.varint(1 if is_pre else 0)
                    await self._send_packet(mc.varint(self._login_plugin_resp) + resp_data)
                    continue
                if pid == self._login_compress:
                    r = mc.Reader(payload, self.pvn)
                    self.compression = r.read_varint()
                    self._zlib = zlib.decompressobj()
                    continue
                if pid == self._login_success:
                    self.state = "login_success"
                    if self._login_ack is not None:
                        await self._send_packet(mc.varint(self._login_ack))
                    break
                if pid == self._login_disconnect:
                    self.kick_reason = _extract_kick(payload, self.pvn) or "kicked"
                    return False
                if pid == self._login_enc:
                    if not self.online:
                        self.kick_reason = "online mode (no auth)"
                        return False
                    continue
                # ignore others
            else:
                return False

            if self._has_config:
                ok = await self._configuration(info)
                if not ok:
                    return False
                self.state = "play"
            else:
                self.state = "play"

            if wait_play:
                await self._wait_join(info)
            return True
        except MCConnError as e:
            self.kick_reason = str(e)
            return False
        finally:
            if self.state != "play" or not wait_play:
                pass

    async def _configuration(self, info):
        # send settings
        sf = info.get("settings_fields") or []
        payload = mc.varint(info.get("settings_id", 0))
        defaults = {
            "locale": "en_US", "viewDistance": 12, "chatFlags": 15,
            "chatColors": True, "skinParts": 255, "mainHand": 1,
            "enableTextFiltering": False, "enableServerListing": True,
            "particleStatus": 0,
        }
        for name, ftype in sf:
            payload += _encode_setting(name, ftype, defaults.get(name))
        await self._send_packet(payload)
        # finish
        cfin = info.get("conf_finish", 2)
        await self._send_packet(mc.varint(cfin))
        # read configuration until finish from server
        cend = info.get("conf_end", 2)
        cdis = info.get("conf_disconnect", 1)
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            pid, payload = await self._read_packet()
            if pid is None:
                return True
            if pid == cend:
                return True
            # play-state packet: server already entered play (some servers
            # skip sending conf_end after the client already finished)
            if pid == self._keep_alive_s2c:
                try:
                    v = mc.Reader(payload, self.pvn).read_i64()
                    await self._send_packet(mc.varint(self._keep_alive_c2s) + mc.i64(v))
                except Exception:
                    pass
                return True
            if pid == info.get("join_game"):
                # server jumped straight into play (skipped conf_end)
                self._join_game = payload
                return True
            if pid == self._play_disconnect:
                self.kick_reason = _extract_kick(payload, self.pvn) or "config kick"
                return False
            if pid == cdis:
                self.kick_reason = _extract_kick(payload, self.pvn) or "config kick"
                return False
        return False

    async def _wait_join(self, info):
        # Wait for join_game (or any play-state packet such as keep_alive,
        # since vanilla servers may not always be paired with an app that
        # sends SpawnInfo). keep_alive only arrives in the play state.
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            pid, payload = await self._read_packet()
            if pid is None:
                return
            if pid == info.get("join_game"):
                self._join_game = payload
                return
            if pid == self._keep_alive_s2c:
                # play state confirmed; echo keepalive and treat as joined
                self._join_game = self._join_game  # keep None if not seen
                try:
                    v = mc.Reader(payload, self.pvn).read_i64()
                    await self._send_packet(mc.varint(self._keep_alive_c2s) + mc.i64(v))
                except Exception:
                    pass
                return
            if pid == self._play_disconnect:
                self.kick_reason = _extract_kick(payload, self.pvn) or "kicked"
                return

    # ---- play state -------------------------------------------------------
    async def chat(self, text):
        info = pkt_info(self.pvn)
        cid = info.get("chat")
        if cid is None:
            return False
        fields = info.get("chat_fields") or [["message", "string"]]

        def _val(name, ftype):
            if name == "message":
                return text
            if name == "timestamp":
                return int(time.time())
            if name == "salt":
                v = int.from_bytes(os.urandom(8), "big")
                # keep signed (i64)
                if v >= (1 << 63):
                    v -= (1 << 64)
                return v
            if name in ("signature", "lastRejectedMessage"):
                return None
            if name == "signedPreview":
                return False
            if name == "previousMessages":
                return []
            if name == "offset":
                return 0
            if name == "acknowledged":
                return b"\x00" * 3
            if name == "checksum":
                return 0
            return None

        body = b""
        for name, ftype in fields:
            body += mc.encode_field(ftype, _val(name, ftype))
        await self._send_packet(mc.varint(cid) + body)
        return True

    async def keepalive(self, value=0):
        # keep_alive id is i64 (8 bytes) in all supported versions
        info = pkt_info(self.pvn)
        cid = info.get("keep_alive_c2s")
        if cid is None:
            return False
        await self._send_packet(mc.varint(cid) + mc.i64(int(value)))
        return True

    async def pong(self, value=0):
        # ping/pong id is i32
        info = pkt_info(self.pvn)
        cid = info.get("pong_c2s")
        if cid is None:
            return False
        await self._send_packet(mc.varint(cid) + mc.i32(int(value)))
        return True

    async def read_one(self):
        return await self._read_packet()


def socket_inet_aton(host):
    import socket
    return socket.inet_aton(host)


def _encode_setting(name, ftype, value):
    """Encode a settings field per its declared type."""
    if ftype == "string":
        return mc.str_field(value)
    if ftype == "i8":
        return bytes([value & 0xFF])
    if ftype in ("varint",):
        return mc.varint(value)
    if ftype == "bool":
        return b"\x01" if value else b"\x00"
    if ftype == "u8":
        return bytes([value & 0xFF])
    # mapper (varint)
    if isinstance(ftype, list) and ftype[0] == "mapper":
        return mc.varint(value)
    return mc.varint(value)
