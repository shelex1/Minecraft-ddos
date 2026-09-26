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
import time

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


def status_of(host, port, protocol=767, timeout=4.0, retries=2):
    """Quick status ping. Returns dict or None.
    Anti-DDoS layers often close connections with 0 bytes, so retry."""
    for _ in range(retries + 1):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(mc.handshake_packet(protocol, host, port, 1))
            s.sendall(mc.status_request_packet())
            data = _read_frame(s, timeout)
            s.close()
            info = mc.parse_status(data)
            if info:
                return info
        except Exception:
            pass
    return None


def _motd_key(info):
    if not info:
        return None
    d = info.get("description", "")
    if isinstance(d, dict):
        d = d.get("text", "")
    return (str(d), str(info.get("version", "")))


def _flatten_component(obj):
    """Flatten a chat component to plain text."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return "".join(_flatten_component(x) for x in obj)
    if isinstance(obj, dict):
        out = obj.get("text", "")
        out += _flatten_component(obj.get("extra", []))
        return out
    return ""


def _extract_version_hint(info):
    """Extract a client-version hint from a status MOTD.
    e.g. MOTD '[1.21.11-26.2]' -> '1.21.11'; 'Paper 1.20.4' -> '1.20.4'.
    Frontend MOTDs usually advertise the backend version."""
    if not info:
        return None
    d = info.get("description", "")
    text = _flatten_component(d) if not isinstance(d, str) else d
    # prefer a version explicitly bracketed in the MOTD: '[1.21.11-26.2]'
    m = re.search(r"\[\s*([0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})?)", text)
    if m:
        return m.group(1)
    # otherwise take the LAST bare version-like token (the first one usually
    # belongs to the proxy version, e.g. 'Velocity 1.7.2-26.1.2')
    ms = re.findall(r"\b([0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})?)\b", text)
    if ms:
        return ms[-1]
    return None



# ---------------------------------------------------------------------------
# SRV / same-host port discovery
# ---------------------------------------------------------------------------

def srv_port(host):
    """Query SRV _minecraft._tcp.<host>. Return port or None (dig-based)."""
    import subprocess
    try:
        out = subprocess.run(["dig", "+short", "SRV", "_minecraft._tcp." + host],
                             capture_output=True, text=True, timeout=6).stdout.strip()
        for line in out.splitlines():
            parts = line.split()
            # format: prio weight port target
            if len(parts) >= 4 and parts[2].isdigit():
                return int(parts[2])
    except Exception:
        pass
    return None


# ports tried first when scanning the same host for extra MC backends
COMMON_PORTS = [25565, 25566, 25567, 25568, 25569, 25570, 25571, 25572,
                25573, 25574, 25575, 25576, 25577, 25578, 25579, 25580,
                25560, 25561, 25562, 25563, 25564]


def port_candidates(front_port):
    """Ordered unique candidate ports for a quick same-host scan."""
    seen, out = set(), []
    for p in COMMON_PORTS:
        if p not in seen:
            seen.add(p); out.append(p)
    for d in range(1, 7):  # neighbours of the known frontend port
        for p in (front_port + d, front_port - d):
            if 1024 < p < 65536 and p not in seen:
                seen.add(p); out.append(p)
    if front_port not in seen:
        out.insert(0, front_port)
    return out


async def tcp_open_ports(ip, ports, timeout=1.2, workers=1000):
    """Fast TCP-connect pre-filter: which ports even accept a connection."""
    async def one(p):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return p
        except Exception:
            return None

    sem = asyncio.Semaphore(workers)

    async def guarded(p):
        async with sem:
            return await one(p)

    res = await asyncio.gather(*(guarded(p) for p in ports))
    return sorted(p for p in res if p)


async def scan_host_ports_async(ip, front_port, protocol=767, timeout=2.0,
                                 workers=48, log=print, limit=64, wide=False):
    """Find MC servers on ONE host; return [{port, info}].
    Catches backends sharing the VPS with the frontend (no prelogin over the
    wire, e.g. Velocity).
    wide=True: fast TCP-connect scan of 1024..65535, then MC status only on
    open ports (much faster than status-probing all 65k ports)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            infos = socket.getaddrinfo(ip, front_port, 0, socket.SOCK_STREAM)
            ip = infos[0][4][0]
        except Exception:
            ip = None
    if not ip:
        return []

    if wide:
        # full-range MC status scan. (A TCP pre-filter does NOT help here:
        # anti-DDoS layers often ACCEPT a TCP connection on every port and
        # only close it after the first MC packet.)
        open_ports = [p for p in range(1024, 65536) if p != front_port]
        log(f"[realip] full MC status scan of {len(open_ports)} ports on {ip} ...")
        t0 = time.time()
    else:
        ports = port_candidates(front_port)
        if limit:
            ports = ports[:limit]
        open_ports = [p for p in ports if p != front_port]

    loop = asyncio.get_running_loop()
    if wide:
        n_workers = max(workers, 150)
        n_timeout = 1.0
        n_retries = 0
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=n_workers)
    else:
        n_workers = max(workers, 32)
        n_timeout = min(timeout, 2.0)
        n_retries = 1
        ex = None

    async def probe(p):
        info = await loop.run_in_executor(ex, status_of, ip, p, protocol,
                                          n_timeout, n_retries)
        return (p, info) if info else None

    try:
        results = [r for r in await asyncio.gather(
            *(probe(p) for p in open_ports)) if r]
    finally:
        if ex:
            ex.shutdown(wait=False)
    if wide:
        log(f"[realip] wide scan took {time.time()-t0:.0f}s")
    found = []
    for p, info in sorted(results):
        v = info.get("version", {}) or {}
        if not v.get("name") and v.get("protocol") is None:
            continue  # not a real MC status answer
        log(f"[realip] host-port {ip}:{p} -> {v.get('name')} (proto {v.get('protocol')})")
        found.append({"port": p, "info": info})
    return found


def scan_host_ports(ip, front_port, protocol=767, timeout=2.0, workers=48,
                    log=print, limit=64, wide=False):
    import asyncio
    return asyncio.run(scan_host_ports_async(ip, front_port, protocol, timeout,
                                             workers, log=log, limit=limit, wide=wide))


async def login_probe_async(host, port, protocol=767, timeout=10.0,
                            username="realipprobe"):
    """One OFFLINE-mode login attempt to a candidate backend.
    Returns {reached, kick, online_mode}:
      online_mode=True -> server kicked 'online mode' => requires a real
                          Mojang account => most likely THE real backend
      reached in ('play','configuration') -> offline-mode (cracked ok).
    """
    from .mcconn import MCConn
    out = {"reached": None, "kick": None, "online_mode": False, "err": None}
    c = MCConn(host, port, timeout=timeout, username=username, online=False)
    c.log = lambda *a: None
    try:
        await c.login(protocol, wait_play=True, timeout=timeout)
        out["reached"] = c.state
        if c.kick_reason:
            out["kick"] = c.kick_reason
            t = c.kick_reason.lower()
            if any(h in t for h in ("online mode", "not authenticated",
                                    "invalid session", "authentication")):
                out["online_mode"] = True
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        out["reached"] = c.state
    finally:
        try:
            await c.close()
        except Exception:
            pass
    return out


async def find_real_ip_async(host, port, version=None, protocol=None, timeout=8,
                              scan_subnet=True, scan_host=True, scan_wide=True,
                              workers=40, log=print):
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
    base_proto = (st or {}).get("version", {}).get("protocol")
    base_uuids = set()
    for pl in ((st or {}).get("players", {}) or {}).get("sample", []) or []:
        if pl.get("id"):
            base_uuids.add(pl["id"].replace("-", "").lower())
    for f in found:
        if f["via"] == "direct":
            f["status"] = st
            continue

    # same-host port scan: find other MC servers on the VPS (a backend behind
    # Velocity does NOT reveal itself via prelogin over the wire)
    if scan_host:
        try:
            host_ip = resolve_host(host, port)[0]
            extra = await scan_host_ports_async(host_ip, port, protocol,
                                                timeout=max(timeout, 1.5),
                                                workers=max(workers, 120), log=log,
                                                wide=scan_wide, limit=0)
            for e in extra:
                found.append({"ip": host_ip, "port": e["port"],
                              "via": "same-host-portscan",
                              "status": e["info"]})
                log(f"[realip] same-host MC server {host_ip}:{e['port']}")
        except Exception as e:
            log(f"[realip] host port-scan error: {type(e).__name__}: {e}")

    # rank same-host candidates:
    #   1) identical MOTD+version
    #   2) status version matches the frontend MOTD version hint
    #      (e.g. MOTD '[1.21.11-26.2]' -> candidate 'Paper 1.21.11')
    #   3) protocol match
    #   4) login probe: online-mode kick => real backend (needs Mojang account)
    host_hits = [f for f in found if f["via"] == "same-host-portscan"]
    best = None
    if host_hits:
        hint = _extract_version_hint(st)
        if hint:
            log(f"[realip] frontend MOTD version hint: {hint}")

        def _sim(f):
            info = f.get("status") or {}
            score = 0
            if base_key and _motd_key(info) == base_key:
                score += 100  # identical MOTD+version -> surely ours
            # same online players as the frontend -> surely the same server
            cand_uuids = set()
            for pl in (info.get("players", {}) or {}).get("sample", []) or []:
                if pl.get("id"):
                    cand_uuids.add(pl["id"].replace("-", "").lower())
            if base_uuids and cand_uuids & base_uuids:
                score += 80
            vname = str((info.get("version") or {}).get("name") or "")
            if hint and hint in vname:
                score += 60
            v = info.get("version", {}) or {}
            if base_proto is not None and v.get("protocol") == base_proto:
                score += 5
            return score

        for f in host_hits:
            f["score"] = _sim(f)

        # candidates worth a login probe: version-hint matches first,
        # then top-scored (max 6 probes)
        hint_hits = [f for f in host_hits
                     if hint and hint in str((f.get("status") or {})
                                             .get("version", {}).get("name") or "")]
        rest = sorted([f for f in host_hits if f not in hint_hits],
                      key=lambda f: (-f["score"], f.get("port", 0)))
        top = (hint_hits + rest)[:6]
        strong = [f for f in host_hits if f["score"] >= 80]
        if len(strong) == 1:
            best = strong[0]
            best["match"] = True
        elif len(host_hits) > 1 and not any(f["score"] >= 100 for f in host_hits):
            log(f"[realip] login-probing {len(top)} candidates to find the real backend...")
            for f in top:
                cand_proto = ((f.get("status") or {}).get("version", {})
                              .get("protocol")) or protocol
                pr = await login_probe_async(f["ip"], f["port"], cand_proto,
                                             timeout=min(timeout, 12.0))
                f["login_probe"] = pr
                log(f"[realip] probe {f['ip']}:{f['port']} -> "
                    f"state={pr['reached']} online_mode={pr['online_mode']} "
                    f"kick={pr['kick']!r}")
                if pr["online_mode"]:
                    f["score"] += 50
                    f["match"] = True
                    f["via"] = "same-host-portscan:online-mode"
                    best = f
                    break
        if best is None:
            best = min(host_hits, key=lambda f: (-f["score"], f.get("port", 0)))
            best["match"] = best["score"] >= 60
        log(f"[realip] best same-host backend guess: "
            f"{best['ip']}:{best['port']} (score {best['score']}, match={best.get('match')})")

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
                 scan_subnet=True, scan_host=True, scan_wide=True, log=print):
    import asyncio
    return asyncio.run(find_real_ip_async(host, port, version, protocol, timeout,
                                          scan_subnet, scan_host=scan_host,
                                          scan_wide=scan_wide, log=log))


def resolve_host(host, port):
    """Resolve hostname -> IP, keep port."""
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        return infos[0][4][0], port
    except Exception:
        return host, port
