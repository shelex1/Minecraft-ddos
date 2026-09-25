"""Automatic proxy fetching, verification and pooling.

Supported: http, socks4, socks5 (also socks5h), with optional user:pass.
Sources: public free-proxy lists. The pool keeps only proxies verified
against the user's own Minecraft server via the MC handshake+status flow.
"""
import asyncio
import random
import re
import time

try:
    import aiohttp  # optional: only needed for fetch_proxies (public lists)
except Exception:
    aiohttp = None

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/raw.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rockerhickey/proxy-list/main/proxies/http.txt",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display&proxy_format=protocolipport&timeout=15000&proxies=http&limit=1000",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display&proxy_format=protocolipport&timeout=15000&proxies=socks4,socks5&limit=1000",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/anonymous.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/elited.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/ssl.txt",
]

LINE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})(?:@|,|$)")


def parse_proxy_line(line: str):
    """Parse 'http://ip:port', 'ip:port', 'socks5://ip:port', 'user:pass@ip:port'."""
    line = line.strip()
    if not line:
        return None
    proto = None
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):\/\/", line)
    if m:
        proto = m.group(1).lower()
        line = line[m.end():]
    userpass = None
    if "@" in line:
        userpass, line = line.rsplit("@", 1)
    if ":" not in line:
        return None
    host, _, port = line.rpartition(":")
    if not host or not port.isdigit():
        return None
    if not (0 < int(port) < 65536):
        return None
    # validate ip
    parts = host.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return None
    proto = proto or "http"
    if proto not in ("http", "https", "socks4", "socks5", "socks5h", "socks4a"):
        proto = "http"
    return {"host": host, "port": int(port), "type": proto,
            "userpass": userpass, "raw": line}


async def fetch_proxies(sources=None, timeout=15, max_workers=12, limit=1500):
    """Download proxy lists and return list of parsed proxies."""
    if aiohttp is None:
        raise RuntimeError("fetch_proxies needs `aiohttp` — run: pip install aiohttp")
    sources = sources or PROXY_SOURCES
    seen = set()
    out = []
    connector = aiohttp.TCPConnector(limit=max_workers * 2)
    async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
        async def grab(url):
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status != 200:
                        return []
                    text = await r.text(errors="replace")
            except Exception:
                return []
            res = []
            for line in text.splitlines():
                p = parse_proxy_line(line)
                if p:
                    key = p["host"] + ":" + str(p["port"]) + p["type"]
                    if key not in seen:
                        seen.add(key)
                        res.append(p)
            return res

        chunks = await asyncio.gather(*[grab(u) for u in sources])
        for ch in chunks:
            out.extend(ch)
        return out[:limit]


def to_url(p: dict) -> str:
    scheme = "http" if p["type"] in ("http", "https") else p["type"]
    auth = ""
    if p.get("userpass"):
        auth = p["userpass"] + "@"
    return f"{scheme}://{auth}{p['host']}:{p['port']}"


class ProxyPool:
    """Holds verified proxies and hands them out to workers."""

    def __init__(self, proxies):
        self.proxies = list(proxies)
        self.dead = set()
        self.lock = asyncio.Lock()
        self.idx = 0
        self.stats = {"used": 0, "failed": 0}

    def size(self):
        return len([p for p in self.proxies if id(p) not in self.dead])

    def take(self) -> dict:
        with self.lock:
            while self.proxies:
                p = self.proxies[self.idx % len(self.proxies)]
                self.idx += 1
                if id(p) not in self.dead:
                    return p
            return None

    def mark_dead(self, p: dict):
        with self.lock:
            self.dead.add(id(p))
            self.stats["failed"] += 1


def verify_one(p: dict, host: str, port: int, protocol: int,
               timeout: float = 8.0, status_check: bool = True):
    """Synchronous verification of a single proxy against an MC server.
    Returns (ok: bool, ms: float)."""
    import socket
    import ssl

    t0 = time.time()
    try:
        if p["type"] in ("http", "https"):
            s = socket.create_connection((p["host"], p["port"]), timeout=timeout)
            buf = bytearray()
            buf += b"CONNECT " + host.encode() + b":" + str(port).encode() + b" HTTP/1.1\r\n"
            buf += b"Host: " + host.encode() + b":" + str(port).encode() + b"\r\n"
            if p.get("userpass"):
                import base64
                buf += b"Proxy-Authorization: Basic " + base64.b64encode(p["userpass"].encode()) + b"\r\n"
            buf += b"Proxy-Connection: keep-alive\r\n\r\n"
            s.sendall(bytes(buf))
            resp = b""
            s.settimeout(timeout)
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    return False, 0
                resp += chunk
            if b" 200" not in resp.split(b"\r\n")[0]:
                s.close()
                return False, 0
            if p["type"] == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
        else:
            s = socket.create_connection((p["host"], p["port"]), timeout=timeout)
            if p["type"] == "socks4" or p["type"] == "socks4a":
                auth = b"\x00"
                if p.get("userpass"):
                    u = p["userpass"].split(":", 1)[1] if ":" in p["userpass"] else p["userpass"]
                    auth = u.encode()
                s.sendall(b"\x04\x01" + struct.pack(">H", port) +
                          socket.inet_aton(host) + auth + b"\x00")
                r = s.recv(8)
                if len(r) < 4 or r[1] != 0x00:
                    s.close()
                    return False, 0
            elif p["type"] in ("socks5", "socks5h"):
                s.sendall(b"\x05\x01\x00")
                r = s.recv(2)
                if len(r) < 2 or r[0] != 5 or r[1] == 0xFF:
                    s.close()
                    return False, 0
                if p.get("userpass"):
                    up = p["userpass"].split(":", 1)
                    u = up[1].encode() if len(up) > 1 else b""
                    s.sendall(b"\x05\x02" + bytes([len(u)]) + u)
                    r = s.recv(2)
                    if r[0] != 5 or r[1] != 0:
                        s.close()
                        return False, 0
                hostbytes = host.encode()
                if p["type"] == "socks5h":
                    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hostbytes)]) + hostbytes +
                              struct.pack(">H", port))
                else:
                    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) +
                              struct.pack(">H", port))
                r = s.recv(4)
                if len(r) < 4 or r[1] != 0:
                    s.close()
                    return False, 0
        # now MC handshake over the tunnel
        from . import protocol as mc
        s.sendall(mc.handshake_packet(protocol, host, port, 1))
        s.sendall(mc.status_request_packet())
        if status_check:
            data = mc.read_frame_sync(s)
            info = mc.parse_status(data)
            if not info:
                s.close()
                return False, 0
        else:
            s.settimeout(timeout)
        s.close()
        return True, (time.time() - t0) * 1000
    except Exception:
        return False, 0


def verify_one_async(p, host, port, protocol, timeout=8.0):
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, verify_one, p, host, port, protocol, timeout)


async def verify_proxies(proxies, host, port, protocol, max_workers=25,
                         timeout=8.0, status_check=True, on_progress=None):
    """Verify a batch of proxies concurrently. Returns (good, bad) lists."""
    good, bad = [], []
    q = asyncio.Queue()
    for p in proxies:
        q.put_nowait(p)

    async def worker():
        while True:
            try:
                p = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                ok, ms = await verify_one_async(p, host, port, protocol, timeout, status_check)
            except Exception:
                ok, ms = False, 0
            if ok:
                good.append(p)
            else:
                bad.append(p)
            if on_progress:
                done = len(good) + len(bad)
                if done % 50 == 0 or done == len(proxies):
                    on_progress(done, len(good), len(bad))
            q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(max_workers)]
    await asyncio.gather(*workers)
    good.sort(key=lambda x: x.get("_ms", 0))
    return good, bad


import struct  # noqa: E402
