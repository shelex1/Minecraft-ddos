"""Bot pool: join, keepalive, chat, anti-bot evasion.

Each bot is an MCConn running a background loop:
  * keepalive (respond to server keepalives)
  * periodic chat (spams chat)
  * respawn handling on kick
  * optional proxy rotation
"""
import asyncio
import json
import os
import random
import time

from .mcconn import MCConn, MCConnError, pkt_info

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
                 name=None, username=None):
        self.idx = idx
        self.host = host
        self.port = port
        self.version = version
        self.proxy = proxy
        self.online = online
        self.log = log or (lambda *a: None)
        self.chat_every = chat_every
        self.username = username or _rand_name()
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
        self.conn = MCConn(self.host, self.port, proxy=self.proxy,
                           username=self.username, online=self.online, log=self._log)
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
                # keepalive loop
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
        """Read packets, answer keepalives, chat periodically."""
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
                    import struct
                    v = struct.unpack(">q", payload[:8])[0]
                    await self.conn.keepalive(v)
                except Exception:
                    pass
            elif pid == info.get("play_disconnect"):
                try:
                    from .protocol import Reader
                    r = Reader(payload, self.conn.pvn)
                    reason = r.read_string()
                except Exception:
                    reason = "kicked"
                self.kicks += 1
                self.joined = False
                self._log("kicked:", reason)
                return
            elif pid == info.get("respawn"):
                # server respawned us; continue
                pass
            elif pid == info.get("ping_s2c"):
                try:
                    import struct
                    v = struct.unpack(">i", payload[:4])[0]
                    await self.conn.pong(v)
                except Exception:
                    pass
            # chat timer
            if time.time() >= next_chat and self.conn.state == "play":
                try:
                    ok = await self.conn.chat(random.choice(_CHAT_MSGS()))
                    if ok:
                        self.chats += 1
                        self._log("chat", random.choice(_CHAT_MSGS())[:30])
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
                 online=False, log=None, chat_every=8.0, usernames=None):
        self.host = host
        self.port = port
        self.version = version
        self.count = count
        self.proxy = proxy
        self.online = online
        self.log = log or (lambda *a: None)
        self.chat_every = chat_every
        self.usernames = usernames or []
        self.bots = []

    def spawn(self, n=None):
        n = n or self.count
        for i in range(len(self.bots), len(self.bots) + n):
            name = self.usernames[i % len(self.usernames)] if self.usernames else None
            b = Bot(i, self.host, self.port, self.version,
                    proxy=self.proxy, online=self.online,
                    log=self.log, chat_every=self.chat_every, name=name,
                    username=name)
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


def _read_varint(data):
    r = 0
    s = 0
    for i, b in enumerate(data[:5]):
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            break
    return r
