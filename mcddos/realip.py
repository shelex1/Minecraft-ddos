"""Real IP discovery behind Velocity / BungeeCord / proxies.

Primary: PreLogin plugin messages (bungeecord:pre_login / velocity:pre_login).
Fallback: subnet scan of the proxy /24 via MC status, comparing motd/version.
"""
import asyncio
import concurrent.futures
import ipaddress
import json
import random
import re
import socket
import struct

from . import protocol as mc
from .versions import guess_version_for_protocol


def _read_frame(sock, timeout=6.0):
    sock.settimeout(timeout)
    return mc.read_frame_sync(sock)


def prelogin_probe(host, port, protocol=767, timeout=6.0, username="probe"):
    """Connect, start login, wait for PreLogin / disconnect.
    Returns (kind, payload) where kind in {bungee, velocity, none}.
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(mc.handshake_packet(protocol, host, port, 2))
        payload = mc.varint(0) + mc.str_field(username)
        s.sendall(mc.varint(len(payload)) + payload)
        deadline = timeout
        import time
        t0 = time.time()
        while time.time() - t0 < deadline:
            data = _read_frame(s, max(0.5, deadline - (time.time() - t0)))
            if not data:
                break
            try:
                r = mc.Reader(data, protocol)
                pid = r.read_varint()
            except Exception:
                break
            if pid == 0x00:
                # PreLogin (login state 0x00 = pre_login in 1.13+; channel string)
                try:
                    channel = r.read_string()
                    rest = data[r.pos:]
                except Exception:
                    channel, rest = "", b""
                if channel == "bungeecord:pre_login":
                    return "bungee", rest
                if channel == "velocity:pre_login":
                    return "velocity", rest
                if "pre_login" in channel or "prelogin" in channel:
                    return "prelogin", rest
            elif pid == 0x02:
                return "success", data
            elif pid == 0x00 and pid == 0:
                continue
            elif pid == 0x04:
                # login_plugin_request -> keep waiting for prelogin
                continue
            elif pid == 0x03:
                # compress
                continue
        s.close()
        return "none", b""
    except Exception:
        return "none", b""


def parse_bungee_prelogin(data: bytes):
    """BungeeCord prelogin data: [VarInt ip (as 32-bit), VarInt port].
    Some builds send the IP as 4 raw bytes. Handle both."""
    out = []
    try:
        r = mc.Reader(data, 0)
        ip = r.read_varint()
        port = r.read_varint()
        if ip > 0xFFFFFFFF:
            # maybe raw bytes variant
            raw = data
            if len(raw) >= 6:
                b0 = raw[0]
                if 0 < b0 < 255:
                    out.append("%d.%d.%d.%d" % (raw[0], raw[1], raw[2], raw[3]))
                    port = struct.unpack(">H", raw[4:6])[0]
                    return out, port
            return out, port
        out.append(".".join(str((ip >> shift) & 0xFF) for shift in (24, 16, 8, 0)))
        return out, port
    except Exception:
        return out, 0


def parse_velocity_prelogin(data: bytes):
    """Velocity prelogin data: JSON array of {host, port, name}."""
    out = []
    try:
        j = json.loads(data.decode("utf-8", "replace"))
        if isinstance(j, list):
            for e in j:
                host = e.get("host") or e.get("address") or ""
                port = e.get("port", 25565)
                if host:
                    out.append(f"{host}:{port}")
    except Exception:
        pass
    return out


def status_of(host, port, protocol=767, timeout=4.0):
    """Quick status ping. Returns dict or None."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(mc.handshake_packet(protocol, host, port, 1))
        s.sendall(mc.status_request_packet())
        data = _read_frame(s)
        s.close()
        return mc.parse_status(data)
    except Exception:
        return None


def _motd_key(info):
    if not info:
        return None
    d = info.get("description", "")
    if isinstance(d, dict):
        d = d.get("text", "")
    return (str(d), str(info.get("version", "")))


async def find_real_ip_async(host, port, version=None, protocol=None, timeout=8,
                              scan_subnet=True, workers=40, log=print):
    """Returns list of dicts: {ip, port, via, status}."""
    found = []
    if protocol is None:
        protocol = 767

    def probe():
        kind, data = prelogin_probe(host, port, protocol, timeout)
        return kind, data

    loop = asyncio.get_running_loop()
    kind, data = await loop.run_in_executor(None, probe)
    log(f"[realip] prelogin kind={kind}")

    if kind == "bungee":
        ips, port2 = parse_bungee_prelogin(data)
        for ip in ips:
            found.append({"ip": ip, "port": port2 or port, "via": "bungeecord-prelogin"})
    elif kind in ("velocity", "prelogin"):
        ips = parse_velocity_prelogin(data)
        for ip in ips:
            h, _, p = ip.rpartition(":")
            found.append({"ip": h, "port": int(p) if p.isdigit() else port,
                          "via": "velocity-prelogin"})
    elif kind == "success":
        log("[realip] server answered login success directly (no proxy detected)")
        found.append({"ip": host, "port": port, "via": "direct"})

    # also check if the host itself is a backend (status check)
    st = await loop.run_in_executor(None, status_of, host, port, protocol, timeout)
    base_key = _motd_key(st)
    for f in found:
        if f["via"] == "direct":
            f["status"] = st
            continue

    if scan_subnet:
        # gather subnet candidates from prelogin results + the host /24
        candidates = set()
        for f in found:
            try:
                net = ipaddress.ip_network(f"{f['ip']}/24", strict=False)
                candidates.update(str(x) for x in net.hosts())
            except Exception:
                pass
        try:
            net = ipaddress.ip_network(f"{host}/24", strict=False)
            candidates.update(str(x) for x in net.hosts())
        except Exception:
            pass
        candidates.discard(host)
        candidates = list(candidates)
        random.shuffle(candidates)
        log(f"[realip] scanning {len(candidates)} subnet candidates...")

        def check(ip):
            info = status_of(ip, port, protocol, timeout=2.0)
            if not info:
                return None
            key = _motd_key(info)
            if key is None:
                return None
            if base_key and key == base_key:
                return ip, "same-motd"
            return ip, "diff-motd"

        hits = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(check, candidates):
                if res:
                    hits.append(res)
        for ip, why in hits:
            if any(f["ip"] == ip for f in found):
                continue
            found.append({"ip": ip, "port": port, "via": f"subnet-scan:{why}"})
            log(f"[realip] found candidate {ip} ({why})")

    return found


def find_real_ip(host, port, version=None, protocol=None, timeout=8,
                 scan_subnet=True, log=print):
    import asyncio
    return asyncio.run(find_real_ip_async(host, port, version, protocol, timeout,
                                          scan_subnet, log=log))


def resolve_host(host, port):
    """Resolve hostname -> IP, keep port."""
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        return infos[0][4][0], port
    except Exception:
        return host, port
