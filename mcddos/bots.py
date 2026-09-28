"""
Пул ботов: вход, keepalive, чат, обход анти-бота.

Каждый бот — это MCConn с фоновым циклом:
  * keepalive (ответы на keepalive сервера)
  * периодический чат (спам в чат)
  * обработка respawn после кика
  * необязательная ротация прокси
"""
import asyncio
import random
import struct
import time

from .mcconn import MCConn, MCConnError, pkt_info
from .mcconn import _extract_kick
from . import bypass

NAMES = [
    "Steve", "Alex", "Herobrine", "Notch", "Jeb", "Dinnerbone",
    "Technoblade", "Ph1LzA", "GeorgeNotFound", "Sapnap", "Tommy", "Tubbo",
    "BadPiggies", "Mango", "Eret", "Welsknight", "Cob", "PolarBear",
    "Soul", "Fuss", "Cleo", "Festive", "Bunny", "LazarLag",
    "xX_Dragon_Xx", "ProGamer", "Speedy", "Builder", "Miner", "Farmer",
    "Smith", "Tinker", "Zombie", "Creeper", "Ender", "Skeleton",
    "Villager", "Guardian", "Shulker", "Piglin", "Warden", "Ghast",
]


class Bot:
    def __init__(self, idx, host, port, version, proxy=None,
                 online=False, log=None, chat_every=8.0,
                 name=None, username=None, signed=False,
                 share_key=True, profile_key=None, offline_uuid=None):
        self.idx = idx
        self.host = host
        self.port = port
        self.version = version
        self.proxy = proxy
        self.online = online
        self.log = log or (lambda *a: None)
        self.chat_every = chat_every
        self.username = username or _rand_name()
        self.signed = signed
        self.share_key = share_key
        self.profile_key = profile_key
        self.offline_uuid = offline_uuid
        self.conn = None
        self.joined = False
        self.kicks = 0
        self.chats = 0
        self.reconnects = 0
        self.task = None
        self._stop = asyncio.Event()
        self._last_log = 0.0

    def _log(self, *a):
        now = time.time()
        if now - self._last_log > 1.0:
            self._last_log = now
            self.log(f"[bot{self.idx:03d} {self.username}] " + " ".join(str(x) for x in a))

    async def _connect_once(self):
        pk = self.profile_key
        if pk is None and self.signed:
            loop = asyncio.get_running_loop()
            pk = await loop.run_in_executor(
                None, bypass.make_profile_key, self.username, self.share_key)
            self.profile_key = pk
            self._log("signed key ready" if self.share_key else "own key ready")
        self.conn = MCConn(self.host, self.port, proxy=self.proxy,
                           username=self.username, online=self.online,
                           log=self._log, profile_key=pk,
                           offline_uuid=self.offline_uuid)
        ok = await self.conn.login(self.version, wait_play=True)
        if ok:
            self.joined = True
            self._log("joined")
        else:
            self.joined = False
            self._log("login fail:", self.conn.kick_reason)
        return ok

    async def _run(self):
        while not self._stop.is_set():
            try:
                if not self.joined:
                    await self._connect_once()
                if not self.joined:
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                    continue
                #  цикл keepalive (поддержание соединения)
                await self._keepalive_loop()
            except MCConnError as e:
                self._log("err", e)
                self.joined = False
            except Exception as e:
                self._log("exc", type(e).__name__, e)
                self.joined = False
            if not self._stop.is_set():
                self.reconnects += 1
                await asyncio.sleep(random.uniform(0.5, 2.0))

    async def _keepalive_loop(self):
        """Читает пакеты, отвечает на keepalive, периодически пишет в чат."""
        next_chat = time.time() + random.uniform(1, self.chat_every)
        while not self._stop.is_set():
            pid, payload = await self.conn.read_one()
            if pid is None:
                self.joined = False
                self.kicks += 1
                return
            info = pkt_info(self.conn.pvn)
            if pid == info.get("keep_alive_s2c"):
                try:
                    v = struct.unpack(">q", payload[:8])[0]
                    await self.conn.keepalive(v)
                except Exception:
                    pass
            elif pid == info.get("play_disconnect"):
                reason = _extract_kick(payload, self.conn.pvn) or "kicked"
                self.kicks += 1
                self.joined = False
                self._log("kicked:", reason)
                return
            elif pid == info.get("respawn"):
                #  сервер прислал respawn; продолжаем
                pass
            elif pid == info.get("ping_s2c"):
                try:
                    v = struct.unpack(">i", payload[:4])[0]
                    await self.conn.pong(v)
                except Exception:
                    pass
            #  таймер чата
            if time.time() >= next_chat and self.conn.state == "play":
                msg = random.choice(_CHAT_MSGS())
                try:
                    ok = await self.conn.chat(msg)
                    if ok:
                        self.chats += 1
                        self._log("chat", msg[:30])
                except Exception:
                    self.joined = False
                    return
                next_chat = time.time() + random.uniform(self.chat_every, self.chat_every * 2)

    def start(self):
        if self.task is None:
            self.task = asyncio.create_task(self._run())

    async def stop(self):
        self._stop.set()
        if self.task:
            try:
                await asyncio.wait_for(self.task, 5)
            except Exception:
                self.task.cancel()
        if self.conn:
            await self.conn.close()


class BotPool:
    def __init__(self, host, port, version, count=20, proxy=None,
                 online=False, log=None, chat_every=8.0, usernames=None,
                 signed=False, share_key=True, offline_uuid=None):
        self.host = host
        self.port = port
        self.version = version
        self.count = count
        self.proxy = proxy
        self.online = online
        self.log = log or (lambda *a: None)
        self.chat_every = chat_every
        self.usernames = usernames or []
        self.signed = signed
        self.share_key = share_key
        self.offline_uuid = offline_uuid
        self.bots = []

    def spawn(self, n=None):
        n = n or self.count
        for i in range(len(self.bots), len(self.bots) + n):
            name = self.usernames[i % len(self.usernames)] if self.usernames else None
            #  ротация прокси: каждый бот получает свой исходящий IP (round-robin)
            px = self.proxy
            if isinstance(px, (list, tuple)):
                px = px[i % len(px)] if px else None
            b = Bot(i, self.host, self.port, self.version,
                    proxy=px, online=self.online,
                    log=self.log, chat_every=self.chat_every, name=name,
                    username=name, signed=self.signed,
                    share_key=self.share_key,
                    offline_uuid=self.offline_uuid)
            self.bots.append(b)
        return self.bots[len(self.bots) - n:] if n else []

    def start_all(self):
        for b in self.bots:
            b.start()

    def stats(self):
        joined = sum(1 for b in self.bots if b.joined)
        kicks = sum(b.kicks for b in self.bots)
        chats = sum(b.chats for b in self.bots)
        return {"total": len(self.bots), "joined": joined, "kicks": kicks, "chats": chats}

    async def stop_all(self):
        for b in self.bots:
            await b.stop()


def _rand_name():
    n = random.choice(NAMES)
    return f"{n}{random.randint(1, 9999)}"


def _CHAT_MSGS():
    return [
        "hello", "hi", "hey", "yo", "w", "lmao", "lol", "brb", "afk",
        "who is online?", "anyone?", "ping", "lag", "gg", "wp", "ez",
        "nice", "cool", "omg", "wtb", "wts", "pvp", "1v1", "duel",
        "best server", "join me", "come to my house", "selling iron",
        "buying diamonds", "free food", "lag lag lag", "cracked",
        "offline mode", "no ban", "trust me", "first time here",
        "where is spawn", "tp to me", "gm", "gn", "thx", "ty",
    ]
