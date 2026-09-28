"""Анти-ддос / анти-бот обход: signed chat, profile key, offline UUID, brand, channels.

Протокольные факты (проверены по minecraft-data + исходникам minecraft-protocol):

1. PROFILE KEY — RSA-2048 (не Ed25519!).
   - 1.19.3+: клиент регистрирует ключ пакетом `chat_session_update`
     (PLAY state, id см. packets.json: chat_session_update).
     Поля: sessionUUID(UUID) + expireTime(i64 ms) + publicKey(varint+SPKI DER)
     + signature(varint+Mojang-подпись).
     Mojang подписывает: signable = UUID(playerUUID) + i64(expireTime) + <raw SPKI DER>,
     алгоритм RSA-SHA1 (profileKeySignatureV2).
   - 1.19.0: ключ в `login_start.signature` (option):
     timestamp(i64) + publicKey(varint+DER) + signature(varint).
     V1: signable = str(timestamp) + "-----BEGIN RSA PUBLIC KEY-----\\n"+base64(DER)+"-----END RSA PUBLIC KEY-----\\n",
     RSA-SHA1. (timestamp = expiresAt в мс.)
   - 1.19.2: то же поле, но V2: signable = UUID(playerUUID) + i64(timestamp) + <raw DER>, RSA-SHA1.
   - Чат подписывает КЛИЕНТ своим RSA-2048 приватным ключом (RSA-SHA256):
       1.19.3+ (useChatSessions):
         signable = i32(1) + UUID(sender) + UUID(session) + i32(index) + i64(salt)
                   + i64(timestamp/1000) + i32(len(msg)) + pstring(msg)
                   [+ i32(n) + buffer(acknowledgements)]  # подписываемые данные: i64 ts + 64-байтная подпись
       1.19.2 (chainedChatWithHashing):
         H = sha256( i64(salt) + i64(ts/1000) + pstring(msg) + i8(70) [+preview]
                     [+ for prev: i8(70)+UUID(sender)+sig ] )
         sig = RSA-SHA256( prevSig + UUID(sender) + H )
       1.19.0:
         sig = RSA-SHA256( i64(salt) + UUID(sender) + i64(ts/1000) + pstring(JSON {"text": msg}) )
   ВНИМАНИЕ: сервер проверяет timestamp < Date.now() (мс) — индекс счётчик с 0.

2. OFFLINE UUID (BungeeCord/CraftBukkit/Velocity): UUID v3 (MD5) от
   "OfflinePlayer:" + name. Ванилла в оффлайн-режиме так же генерит.
   Это спасает от плагинов, флазящих на zero-UUID / random-UUID ботов.

3. BRAND: minecraft:brand = "vanilla" (play custom_payload, channel + restBuffer).
   Vanilla клиент шлёт в 1.20.2+ через config custom_payload, в <=1.19.4 — play.

4. REGISTER: minecraft:register = последовательность cstring (NUL-terminated).

5. Geyser ping: канал "com/geysermc:ping" (data: varint 0x02) -> ответ "com/geysermc:pong"
   (data: varint 0x01). Используется Geyser-совместимыми бранд-проверками.

Чистый Python (cryptography не используем), только stdlib + hashlib.
"""
import base64
import hashlib
import math
import os
import time
import uuid as _uuid

# C-ускорение (опционально): gmpy2 даёт pow/isprime/invert на mpz в ~10-30x быстрее
# встроенных pow() на 1024-бит. Fallback — чистый Python (stdlib).
try:
    import gmpy2 as _gmpy2
    _HAVE_GMPY2 = True
except ImportError:
    _gmpy2 = None
    _HAVE_GMPY2 = False

from . import protocol as mc

# Mojang master key (public) — только для локальной проверки в тестах;
# для оффлайн-бота нужен СВОЙ ключ + (опц.) реальный Mojang-токен.
MOJANG_RSA_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylB4B6m5lz7jwrcFz6Fd\n"
    "/fnfUhcvlxsTSn5kIK/2aGG1C3kMy4VjhwlxF6BFUSnfxhNswPjh3ZitkBxEAFY2\n"
    "5uzkJFRwHwVA9mdwjashXILtR6OqdLXXFVyUPIURLOSWqGNBtb08EN5fMnG8iFLg\n"
    "EJIBMxs9BvF3s3/FhuHyPKiVTZmXY0WY4ZyYqvoKR+XjaTRPPvBsDa4WI2u1zxXM\n"
    "eHlodT3lnCzVvyOYBLXL6CJgByuOxccJ8hnXfF9yY4F0aeL080Jz/3+EBNG8RO4B\n"
    "yhtBf4Ny8NQ6stWsjfeUIvH7bU/4zCYcYOq4WrInXHqS8qruDmIl7P5XXGcabuzQ\n"
    "stPf/h2CRAUpP/PlHXcMlvewjmGU6MfDK+lifScNYwjPxRo4nKTGFZf/0aqHCh/E\n"
    "AsQyLKrOIYRE0lDG3bzBh8ogIMLAugsAfBb6M3mqCqKaTMAf/VAjh5FFJnjS+7bE\n"
    "+bZEV0qwax1CEoPPJL1fIQjOS8zj086gjpGRCtSy9+bTPTfTR/SJ+VUB5G2IeCIt\n"
    "kNHpJX2ygojFZ9n5Fnj7R9ZnOM+L8nyIjPu3aePvtcrXlyLhH/hvOfIOjPxOlqW+\n"
    "O5QwSFP4OEcyLAUgDdUgyW36Z5mB285uKW/ighzZsOTevVUG2QwDItObIV6i8RCx\n"
    "FbN2oDHyPaO5j1tTaBNyVt8CAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n"
)

# ---------------------------------------------------------------------------
# Чистый RSA (2048) + SHA-1/SHA-256 + DER. Без cryptography.
# ---------------------------------------------------------------------------


# DigestInfo OID prefixes (PKCS#1 v1.5): OID хЕША (не схемы подписи).
#    SHA-1   = OID 1.3.14.3.2.26        -> байты 2b 0e 03 02 1a
#    SHA-256 = OID 2.16.840.1.101.3.4.2.1 -> 60 86 48 01 65 03 04 02 01 (NIST; Java/openssl)
_DIGEST_INFO_PREFIX = {
    "sha1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "sha256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
}


class _RSACtx:
    """Минимальный RSA: keygen / sign / verify / SPKI DER / PKCS#1 v1.5 PEM."""

    def __init__(self, n, e, d=None, p=None, q=None, crt=False):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.crt = crt
        if crt and d and p and q:
            self.dmp1 = d % (p - 1)
            self.dmq1 = d % (q - 1)
            self.qinv = pow(q, -1, p)

    @staticmethod
    def _mr(n):
        # Miller-Rabin: gmpy2.isprime (C, 10 раундов) или фикс. основания {2,3,5,7}
        if _HAVE_GMPY2:
            return bool(_gmpy2.is_prime(_gmpy2.mpz(n), 10))
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for a in (2, 3, 5, 7):
            a %= n
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def _small_primes(limit):
        """Сита Эратосфена: все простые < limit (кэш на уровне модуля)."""
        sp = globals().get('_SMALL_PRIMES')
        if sp is not None:
            return sp
        sieve = bytearray([1]) * (limit + 1)
        sieve[0:2] = b'\x00\x00'
        import math as _m
        for i in range(2, int(_m.isqrt(limit)) + 1):
            if sieve[i]:
                step = i
                start = i * i
                sieve[start:limit + 1:step] = bytearray(len(range(start, limit + 1, step)))
        primes = [i for i in range(2, limit + 1) if sieve[i]]
        globals()['_SMALL_PRIMES'] = primes
        return primes

    @classmethod
    def generate(cls, bits=2048, rng=os.urandom):
        def is_prime(n, k=8):
            if n < 2:
                return False
            for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                if n % sp == 0:
                    return n == sp
            d, r = n - 1, 0
            while d % 2 == 0:
                d //= 2
                r += 1
            for _ in range(k):
                a = int.from_bytes(rng(32), "big") % (n - 3) + 1
                x = pow(a, d, n)
                if x in (1, n - 1):
                    continue
                for _ in range(r - 1):
                    x = x * x % n
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        half = bits // 2
        small = cls._small_primes(4096)
        def trial(n):
            for sp in small:
                if n % sp == 0:
                    return n == sp
            return cls._mr(n)
        while True:
            p = int.from_bytes(rng(half // 8), "big")
            p |= 1 << (half - 1) | 1
            if not trial(p):
                continue
            q = int.from_bytes(rng(half // 8), "big")
            q |= 1 << (half - 1) | 1
            if q == p or not trial(q):
                continue
            n = p * q
            if n.bit_length() < bits:
                continue
            phi = (p - 1) * (q - 1)
            e = 65537
            if math.gcd(e, phi) != 1:
                e = 3
            d = pow(e, -1, phi)
            return cls(n, e, d, p, q, crt=True)

    def _pad_pkcs1_sha(self, digest, digest_info_hdr):
        k = (self.n.bit_length() + 7) // 8
        tlen = len(digest_info_hdr) + len(digest)
        ps = b"\xff" * (k - tlen - 3)
        em = b"\x00" + b"\x01" + ps + b"\x00" + digest_info_hdr + digest
        return em

    def sign(self, msg, sha="sha256"):
        h = getattr(hashlib, sha)(msg).digest()
        hdr = _DIGEST_INFO_PREFIX[sha]
        em = self._pad_pkcs1_sha(h, hdr)
        m = int.from_bytes(em, "big")
        if _HAVE_GMPY2:
            n = _gmpy2.mpz(self.n)
            if self.crt:
                p = _gmpy2.mpz(self.p)
                q = _gmpy2.mpz(self.q)
                mi = pow(_gmpy2.mpz(m), _gmpy2.mpz(self.dmp1), p)
                mj = pow(_gmpy2.mpz(m), _gmpy2.mpz(self.dmq1), q)
                h = (_gmpy2.mpz(self.qinv) * (mi - mj)) % p
                res = mj + h * q
            else:
                res = pow(_gmpy2.mpz(m), _gmpy2.mpz(self.d), n)
            return int(res).to_bytes((self.n.bit_length() + 7) // 8, "big")
        if self.crt:
            mi = pow(m, self.dmp1, self.p)
            mj = pow(m, self.dmq1, self.q)
            h = (self.qinv * (mi - mj)) % self.p
            return (mj + h * self.q).to_bytes((self.n.bit_length() + 7) // 8, "big")
        return pow(m, self.d, self.n).to_bytes((self.n.bit_length() + 7) // 8, "big")

    def verify(self, sig, msg, sha="sha256"):
        s = int.from_bytes(sig, "big")
        if _HAVE_GMPY2:
            m = int(pow(_gmpy2.mpz(s), _gmpy2.mpz(self.e), _gmpy2.mpz(self.n)))
        else:
            m = pow(s, self.e, self.n)
        k = (self.n.bit_length() + 7) // 8
        em = m.to_bytes(k, "big")
        h = getattr(hashlib, sha)(msg).digest()
        hdr = _DIGEST_INFO_PREFIX[sha]
        return em == self._pad_pkcs1_sha(h, hdr)

    # ---- DER ----
    @staticmethod
    def _der_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    @staticmethod
    def _der_int(b):
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + _RSACtx._der_len(len(b)) + b

    @classmethod
    def _pkcs1_der(cls, n, e):
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        eb = e.to_bytes((e.bit_length() + 7) // 8, "big")
        inner = cls._der_int(nb) + cls._der_int(eb)
        return b"\x30" + cls._der_len(len(inner)) + inner

    def public_der(self):
        """SPKI DER (SubjectPublicKeyInfo) для RSA-PUBLIC-KEY (PKCS#1) внутри."""
        p1 = self._pkcs1_der(self.n, self.e)
        alg = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
        bits = b"\x00" + p1  # unused-bit-count = 0
        bs = b"\x03" + self._der_len(len(bits)) + bits
        inner = alg + bs
        return b"\x30" + self._der_len(len(inner)) + inner

    def to_public_pem_pkcs1(self):
        p1 = self._pkcs1_der(self.n, self.e)
        b64 = base64.b64encode(p1).decode()
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN RSA PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END RSA PUBLIC KEY-----\n"

    def to_public_pem_spki(self):
        b64 = base64.b64encode(self.public_der()).decode()
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

    @classmethod
    def from_spki_der(cls, der):
        """Разбирает SPKI DER -> (n, e)."""
        def rd(buf, i):
            #  -> (тег, значение, начало содержимого, конец TLV)
            t = buf[i]; i += 1
            l = buf[i]; i += 1
            if l & 0x80:
                nrb = l & 0x7f
                l = int.from_bytes(buf[i:i + nrb], "big"); i += nrb
            v = buf[i:i + l]
            return t, v, i, i + l
        def rdi(x, j):
            #  INTEGER -> (тег, байты, конец)
            tt = x[j]; j += 1
            ll = x[j]; j += 1
            if ll & 0x80:
                nr = ll & 0x7f
                ll = int.from_bytes(x[j:j + nr], "big"); j += nr
            v = x[j:j + ll]
            return tt, v, j + ll
        #  внешний SEQUENCE
        t, _, c1, _ = rd(der, 0)
        assert t == 0x30
        #  SEQUENCE алгоритма (AlgorithmIdentifier)
        t, _, _, e2 = rd(der, c1)
        assert t == 0x30
        #  bit string (открытый ключ субъекта)
        t, bs, _, _ = rd(der, e2)
        assert t == 0x03
        p1 = bs[1:]  # отбрасываем unused-bit-count
        #  SEQUENCE публичного RSA-ключа (RSAPublicKey)
        t, inner, c4, _ = rd(p1, 0)
        assert t == 0x30
        _, n, j = rdi(inner, 0)
        _, e, _ = rdi(inner, j)
        return cls(int.from_bytes(n, "big"), int.from_bytes(e, "big"))


# ---------------------------------------------------------------------------
#  Профильный ключ (1.19.3+)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Общий ключ на волну ботов: генерация RSA-2048 ~1-5 c (gmpy2) — при 100 ботах
# по одному ключу на бота это 100 генераций. --share-key: одна генерация на волну,
# каждый бот шлёт тот же public key (сервер это допустит: vanilla-клиент тоже
# переиспользует ключ пока не истёк). Сессия подписи (sessionUUID) — своя на бота.
# ---------------------------------------------------------------------------

_shared_key_lock = None
_shared_key = None


def get_shared_key(bits=2048):
    """Один RSA-2048 на волну (ленивая генерация, thread-safe)."""
    global _shared_key_lock, _shared_key
    if _shared_key is not None:
        return _shared_key
    import threading
    if _shared_key_lock is None:
        _shared_key_lock = threading.Lock()
    with _shared_key_lock:
        if _shared_key is None:
            _shared_key = _RSACtx.generate(bits)
    return _shared_key


def reset_shared_key():
    global _shared_key
    _shared_key = None


class ProfileKey:
    """RSA-2048 профильный ключ + сессия подписи чата (1.19.3+)."""

    def __init__(self, rsa: _RSACtx, session_uuid: bytes = None,
                 expire_ms: int = None, mojang_signature: bytes = None,
                 player_uuid: bytes = None):
        self.rsa = rsa
        self.public_der = rsa.public_der()
        self.session_uuid = session_uuid or _uuid.uuid4().bytes
        self.expire_ms = expire_ms or (int(time.time() * 1000) + 47 * 3600 * 1000)
        # Mojang-подпись ключа (нужна только если сервер проверяет mojang-подпись;
        # в оффлайн-режиме сервер обычно не может проверить -> None = не шлём как есть).
        self.mojang_signature = mojang_signature
        self.player_uuid = player_uuid
        self._index = 0
        self._last_chain_sig = None  # для 1.19.2 chained

    def mojang_signable_v2(self, player_uuid, expire_ms, der):
        return player_uuid + mc.i64(expire_ms) + der

    def mojang_signable_v1(self, expire_ms, der):
        pem = self.rsa.to_public_pem_pkcs1()
        return str(expire_ms).encode() + pem.encode()

    def chat_signable_v193(self, msg: str, ts_ms: int, salt: int, acks=b""):
        """Формула подписываемых данных для 1.19.3+:
        i32(1) + senderUUID + sessionUUID + i32(index) + i64(salt)
        + i64(ts/1000) + i32(len) + pstring(msg) [+ acks]
        """
        mb = msg.encode("utf-8")
        idx = self._index
        self._index += 1
        out = mc.i32(1) + self.player_uuid + self.session_uuid + mc.i32(idx) + mc.i64(salt)
        out += mc.i64(ts_ms // 1000) + mc.i32(len(mb)) + mc.varint(len(mb)) + mb
        if acks:
            out += mc.i32(len(acks)) + acks
        else:
            out += mc.i32(0)
        return out

    def sign_chat_v193(self, msg, ts_ms=None, salt=None, acks=b""):
        ts_ms = ts_ms if ts_ms is not None else int(time.time() * 1000)
        salt = salt if salt is not None else (int.from_bytes(os.urandom(8), "big") - (1 << 64))
        s = self.chat_signable_v193(msg, ts_ms, salt, acks)
        return self.rsa.sign(s, "sha256"), ts_ms, salt

    def sign_chat_190(self, msg, ts_ms=None, salt=None):
        import json as _json
        ts_ms = ts_ms if ts_ms is not None else int(time.time() * 1000)
        salt = salt if salt is not None else (int.from_bytes(os.urandom(8), "big") - (1 << 64))
        s = mc.i64(salt) + self.player_uuid + mc.i64(ts_ms // 1000) + mc.str_field(_json.dumps({"text": msg}))
        return self.rsa.sign(s, "sha256"), ts_ms, salt

    def sign_chat_192(self, msg, ts_ms=None, salt=None, prev=None):
        """1.19.2 chained. prev: (sender_uuid, signature) или None."""
        ts_ms = ts_ms if ts_ms is not None else int(time.time() * 1000)
        salt = salt if salt is not None else (int.from_bytes(os.urandom(8), "big") - (1 << 64))
        mb = msg.encode("utf-8")
        h = hashlib.sha256()
        h.update(mc.i64(salt) + mc.i64(ts_ms // 1000) + mc.varint(len(mb)) + mb + b"\x46")
        if prev:
            su, ssig = prev
            h.update(b"\x46" + su + ssig)
        digest = h.digest()
        body = (self._last_chain_sig or b"") + self.player_uuid
        sig = self.rsa.sign(body + digest, "sha256")
        self._last_chain_sig = sig
        return sig, ts_ms, salt


# ---------------------------------------------------------------------------
# Offline UUID (BungeeCord / CraftBukkit / Velocity)
# ---------------------------------------------------------------------------


def make_profile_key(name: str, share: bool = False, expire_ms=None,
                     session_uuid=None, mojang_signature=None):
    """Per-bot ProfileKey.

    share=True -> RSA берётся из общего кэша на волну (get_shared_key),
    share=False -> свой RSA-2048 (дороже, ~1-9 c).
    session_uuid / player_uuid / expire — свои на бота.
    player_uuid = offline v3 UUID от имени (совпадает с тем, что в login_start).
    """
    rsa = get_shared_key() if share else _RSACtx.generate(2048)
    return ProfileKey(rsa,
                      session_uuid=session_uuid,
                      expire_ms=expire_ms,
                      mojang_signature=mojang_signature,
                      player_uuid=offline_uuid_bytes(name))


def offline_uuid_bytes(name: str) -> bytes:
    """UUID v3 (MD5) от 'OfflinePlayer:'+name — как ванилла/прокси в оффлайн-режиме."""
    h = bytearray(hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest())
    h[6] = (h[6] & 0x0F) | 0x30
    h[8] = (h[8] & 0x3F) | 0x80
    return bytes(h)


def offline_uuid_str(name: str) -> str:
    return str(_uuid.UUID(bytes=offline_uuid_bytes(name)))


# ---------------------------------------------------------------------------
#  Плагин-каналы: brand / register / geyser
# ---------------------------------------------------------------------------

BRAND_CHANNEL = "minecraft:brand"
REGISTER_CHANNEL = "minecraft:register"
UNREGISTER_CHANNEL = "minecraft:unregister"
GEYSER_PING = "com/geysermc:ping"
GEYSER_PONG = "com/geysermc:pong"

# Каналы, которые vanilla-клиент регистрирует (1.20.2+):
#   com/mojang/realms, com/mojang/realms_server, com/mojang/trial_reports,
#   com/mojang/python(?), minecraft:difficulty_lock, com/mojang/ping (geyser)
VANILLA_REGISTER_CHANNELS = [
    "com/mojang/realms",
    "com/mojang/realms_server",
    "com/mojang/trial_reports",
    "minecraft:difficulty_lock",
    "com/mojang/ping",
]


def _cstring(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def custom_payload(channel: str, data: bytes) -> bytes:
    """Body пакета custom_payload: string(channel) + restBuffer(data)."""
    return mc.str_field(channel) + data


def brand_payload(brand: str = "vanilla") -> bytes:
    return custom_payload(BRAND_CHANNEL, mc.str_field(brand))


def register_payload(channels) -> bytes:
    return custom_payload(REGISTER_CHANNEL, b"".join(_cstring(c) for c in channels))


def geyser_ping_payload() -> bytes:
    return custom_payload(GEYSER_PING, mc.varint(0x02))


def geyser_pong_payload() -> bytes:
    return custom_payload(GEYSER_PONG, mc.varint(0x01))


__all__ = [
    "_RSACtx", "ProfileKey", "offline_uuid_bytes", "offline_uuid_str",
    "custom_payload", "brand_payload", "register_payload",
    "geyser_ping_payload", "geyser_pong_payload",
    "MOJANG_RSA_PUBLIC_KEY_PEM", "VANILLA_REGISTER_CHANNELS",
    "get_shared_key", "reset_shared_key", "_HAVE_GMPY2",
    "make_profile_key",
    "BRAND_CHANNEL", "REGISTER_CHANNEL", "UNREGISTER_CHANNEL",
    "GEYSER_PING", "GEYSER_PONG",
]
