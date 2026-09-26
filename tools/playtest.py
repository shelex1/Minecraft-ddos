#!/usr/bin/env python3
"""
PlayTest — заход на сервер КАК РЕАЛЬНЫЙ ИГРОК (self-test)
=========================================================
Подключается к MC-серверу как настоящий игрок и отчитывается, что произошло:
  * авто-определяет версию сервера (если не указана -v)
  * находит РЕАЛЬНЫЙ IP бэкенда (за Velocity/Bungee: prelogin + subnet-скан)
  * делает полный логин (handshake -> login -> configuration -> play)
  * держит соединение (keepalive), пишет в чат, переживает кики/respawn
  * держится на сервере T секунд и выдаёт подробный отчёт (JSON + сводка)

Сигналы, которые считаем:
  - join_game           => реально в мире (успех)
  - kick (play/login)   => кик + причина (капча/регистрация/whitelist/...)
  - online mode         => нужен аккаунт (не cracked)
  - keepalive ok        => соединение живое
  - chat sent           => умеет писать в чат

Примеры:
  python3 tools/playtest.py play.example.com 25565
  python3 tools/playtest.py play.example.com 25565 -v 1.20.4 -t 90
  python3 tools/playtest.py play.example.com 25565 --chat "hi, testing" --stay 60
  python3 tools/playtest.py play.example.com 25565 --fetch 300   # через прокси
  python3 tools/playtest.py play.example.com 25565 --proxy socks5://ip:port
"""
import argparse
import asyncio
import json
import os
import random
import re
import socket
import sys
import time

# allow running from any directory (package may be in a parent dir)
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE), os.path.dirname(os.path.dirname(_HERE)), os.getcwd()):
    if os.path.isdir(os.path.join(_p, "mcddos")):
        sys.path.insert(0, _p)
        break

from mcddos.versions import VERSIONS, guess_version_for_protocol, protocol_of  # noqa: E402
from mcddos.mcconn import MCConn, MCConnError, pkt_info, _extract_kick          # noqa: E402
from mcddos.protocol import Reader                                              # noqa: E402
from mcddos import realip as realip_mod                                         # noqa: E402
from mcddos.proxies import parse_proxy_line, fetch_proxies                      # noqa: E402

# protocols most-likely first (subset of 735..777)
ALL_PROTOCOLS = [775, 774, 773, 772, 771, 770, 769, 768, 767, 766, 765,
                 764, 763, 762, 761, 760, 759, 758, 757, 756, 755, 754,
                 753, 751, 735]
LIKELY = [775, 774, 773, 772, 771, 767, 765, 763, 760]

CAPTCHA_HINTS = ["капча", "captcha", "recaptcha", "hcaptcha", "geetest",
                 "datadome", "turnstile", "cloudflare"]
REG_HINTS = ["регистрац", "register", "/reg", "sign up", "authme", "register your"]
CHAT_MSGS = ["hi", "hello", "gm", "anyone there?", "testing connection", "ping",
             "w", "nice server", "first time here"]


def log(*a):
    print(*a, flush=True)


def extract_kick_text(payload, pvn):
    """Re-export from mcconn for clarity."""
    return _extract_kick(payload, pvn)


def classify_kick(text):
    t = (text or "").lower()
    if not t:
        return None
    if any(h in t for h in CAPTCHA_HINTS):
        return "captcha"
    if any(h in t for h in REG_HINTS):
        return "registration"
    if any(h in t for h in ("version", "верси", "too old", "too new", "update",
                            "incompatible", "outdated", "play on")):
        return "wrong_version"
    if any(h in t for h in ("whitelist", "белый", "whitelisted", "staff only")):
        return "whitelist"
    if any(h in t for h in ("full", "макс", "no free slots")):
        return "server_full"
    if any(h in t for h in ("banned", "бан", "timed out", "timeout", "expired")):
        return "ban_or_timeout"
    if any(h in t for h in ("online mode", "not authenticated", "invalid session",
                            "offline", "authentication")):
        return "online_mode"
    return "other"


# ---------------------------------------------------------------------------
# phase 1: auto version detect (status sweep)
# ---------------------------------------------------------------------------
async def detect_version(host, port, proxies, timeout, workers, direct=True):
    """Return (pvn, info, working_label, working_proxy) or (None,...)."""
    sources = []
    if direct:
        sources.append(("direct", None))
    for p in proxies:
        sources.append((f"{p['type']} {p['host']}:{p['port']}", p))

    hit = {"r": None}
    sem = asyncio.Semaphore(workers)
    done = 0
    total = len(sources) * len(LIKELY)

    async def try_status(label, proxy, pvn):
        nonlocal done
        c = MCConn(host, port, timeout=timeout, proxy=proxy)
        c.log = lambda *a: None
        try:
            async with sem:
                d = await c.status(pvn=pvn)
        except Exception:
            d = None
        finally:
            try:
                await c.close()
            except Exception:
                pass
        done += 1
        if isinstance(d, dict) and not hit["r"]:
            hit["r"] = (label, proxy, pvn, d)
            log(f"  [~{done}/{total}] STATUS via {label}: pvn={pvn} "
                f"ver={d.get('version', {}).get('name')}")

    t0 = time.time()
    await asyncio.gather(*(try_status(l, pr, p) for l, pr in sources for p in LIKELY))
    log(f"  version sweep: {done} probes in {time.time()-t0:.0f}s")

    if hit["r"]:
        label, proxy, pvn, d = hit["r"]
        v = d.get("version", {})
        return int(v.get("protocol", pvn)), d, label, proxy
    return None, None, None, None


# ---------------------------------------------------------------------------
# phase 2: real player login + keepalive + chat + stay
# ---------------------------------------------------------------------------
async def play_once(host, port, pvn, name, stay, chat_msg, proxy, timeout):
    """One full real-player session. Returns a report dict."""
    _t0 = time.time()
    rep = {"joined": False, "join_game": False, "kick": None, "kick_type": None,
           "online_mode": False, "backend": None, "keeps": 0, "chats": 0,
           "respawns": 0, "state": "none", "err": None, "duration": 0.0,
           "seen_packets": []}
    c = MCConn(host, port, timeout=timeout, proxy=proxy, username=name, online=False)
    c.log = lambda *a: None
    info = pkt_info(pvn)
    ka_s2c = info.get("keep_alive_s2c")
    ping_s2c = info.get("ping_s2c")
    play_disc = info.get("play_disconnect")
    respawn_id = info.get("respawn")
    join_game_id = info.get("join_game")

    try:
        ok = await c.login(pvn, wait_play=True, timeout=timeout)
        rep["state"] = c.state
        rep["backend"] = c.real_backend
        if c.kick_reason:
            rep["kick"] = c.kick_reason
            rep["kick_type"] = classify_kick(c.kick_reason)
        if ok:
            rep["joined"] = True
            if c._join_game is not None:
                rep["join_game"] = True
                rep["seen_packets"].append("join_game")
            # stay & keep alive
            t_end = time.time() + stay
            next_chat = time.time() + random.uniform(2, 8)
            while time.time() < t_end and not c._closed:
                try:
                    pid, payload = await asyncio.wait_for(c.read_one(), timeout=2.0)
                except asyncio.TimeoutError:
                    continue
                if pid is None:
                    rep["state"] = "closed"
                    break
                if pid == ka_s2c:
                    try:
                        v = Reader(payload, pvn).read_i64()
                        await c.keepalive(v)
                        rep["keeps"] += 1
                    except Exception:
                        pass
                elif pid == ping_s2c:
                    try:
                        v = Reader(payload, pvn).read_i32()
                        await c.pong(v)
                    except Exception:
                        pass
                elif pid == play_disc:
                    rep["kick"] = extract_kick_text(payload, pvn) or "kicked"
                    rep["kick_type"] = classify_kick(rep["kick"])
                    break
                elif pid == respawn_id:
                    rep["respawns"] += 1
                elif pid == join_game_id and not rep["join_game"]:
                    rep["join_game"] = True
                    rep["seen_packets"].append("join_game")
                if time.time() >= next_chat:
                    msg = chat_msg or random.choice(CHAT_MSGS)
                    try:
                        if await c.chat(msg):
                            rep["chats"] += 1
                    except Exception:
                        pass
                    next_chat = time.time() + random.uniform(8, 16)
        else:
            rep["seen_packets"].append("login-fail")
    except MCConnError as e:
        rep["err"] = f"{type(e).__name__}: {e}"
    except Exception as e:
        rep["err"] = f"{type(e).__name__}: {e}"
    finally:
        rep["duration"] = time.time() - _t0
        try:
            await c.close()
        except Exception:
            pass
    return rep


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
async def amain(args):
    host, port = args.host, args.port
    result = {"host": host, "port": port, "username": args.name,
              "version": None, "protocol": None, "real_ip": None,
              "real_ip_source": None, "joined": False, "join_game": False,
              "kick": None, "kick_type": None, "online_mode": False,
              "keeps": 0, "chats": 0, "respawns": 0, "state": None,
              "working_source": None, "verdict": None, "notes": [],
              "kick_texts": []}
    t_start = time.time()

    # ---- phase 0: DNS / TCP ----
    log(f"\n=== [0] DNS/TCP :: {host}:{port} ===")
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)})
        log(f"  A: {ips}")
        result["dns_ips"] = ips
    except Exception as e:
        log(f"  DNS error: {e}")
    try:
        s = socket.create_connection((host, port), timeout=8); s.close()
        log("  TCP: open")
    except Exception as e:
        log(f"  TCP: closed ({type(e).__name__})")

    # ---- proxies ----
    proxies = []
    seen = set()

    def add_p(p):
        key = (p["host"], p["port"], p["type"])
        if key not in seen:
            seen.add(key)
            proxies.append(p)

    for spec in (args.proxy or []):
        for part in spec.split(","):
            p = parse_proxy_line(part.strip())
            if p:
                add_p(p)
    if args.proxy_file:
        with open(args.proxy_file) as f:
            for line in f:
                p = parse_proxy_line(line)
                if p:
                    add_p(p)
    if args.fetch:
        log(f"\n  fetching up to {args.fetch} free proxies ...")
        got = await fetch_proxies(limit=args.fetch)
        for p in got:
            add_p(p)
        log(f"  +{len(got)} proxies (total {len(proxies)})")
    if args.max_proxies:
        proxies = proxies[:args.max_proxies]

    # ---- phase 1: version ----
    log(f"\n=== [1] Version detect ===")
    pvn = None
    if args.version:
        pvn = protocol_of(args.version) if not isinstance(args.version, int) else args.version
        result["version"] = args.version
        result["protocol"] = pvn
        log(f"  using -v {args.version} (protocol {pvn})")
    else:
        pvn, d, label, wproxy = await detect_version(host, port, proxies,
                                                     args.timeout, args.workers,
                                                     direct=not args.no_direct)
        if pvn:
            result["protocol"] = pvn
            result["version"] = (d or {}).get("version", {}).get("name") or guess_version_for_protocol(pvn)
            result["working_source"] = label
            result["notes"].append(f"version via {label}")
            pl = (d or {}).get("players", {})
            log(f"  -> version {result['version']} (protocol {pvn}) via {label}")
            log(f"     players {pl.get('online')}/{pl.get('max')}")
        else:
            result["notes"].append("version not detected (status sweep failed)")
            log("  -> NOT DETECTED")

    # ---- phase 2: real player login(s) ----
    log(f"\n=== [2] Real-player login (name={args.name}) ===")
    if pvn is None:
        pvn = 767  # best guess
        result["notes"].append("no version detected; guessing protocol 767")

    sources = []
    if not args.no_direct:
        sources.append(("direct", None))
    for p in proxies[: args.max_proxies]:
        sources.append((f"{p['type']} {p['host']}:{p['port']}", p))

    for label, proxy in sources:
        log(f"\n  --- attempt via {label} ---")
        rep = await play_once(host, port, pvn, args.name, args.stay,
                              args.chat, proxy, args.login_timeout)
        rep["_label"] = label
        if rep["backend"] and not result["real_ip"]:
            ip, rport, kind = rep["backend"]
            result["real_ip"] = ip
            result["real_ip_source"] = f"{kind}:pre_login:{rport} via {label}"
            result["notes"].append(f"prelogin via {label}: {ip}:{rport} ({kind})")
        if rep["kick"] and rep["kick"] not in result["kick_texts"]:
            result["kick_texts"].append(rep["kick"])
        log(f"    joined={rep['joined']} join_game={rep['join_game']} "
            f"keeps={rep['keeps']} chats={rep['chats']} state={rep['state']} "
            f"kick={rep['kick']!r}")
        if rep["err"]:
            log(f"    err: {rep['err']}")
        if rep["joined"]:
            result["working_source"] = label
            result["joined"] = True
            result["join_game"] = rep["join_game"]
            result["keeps"] = rep["keeps"]
            result["chats"] = rep["chats"]
            result["respawns"] = rep["respawns"]
            result["state"] = "play"
            if rep["kick"]:
                result["kick"] = rep["kick"]
                result["kick_type"] = rep["kick_type"]
            break
        # if we got a definitive kick (captcha/reg/whitelist/online-mode), stop
        if rep["kick_type"] in ("captcha", "registration", "whitelist", "online_mode"):
            result["kick"] = rep["kick"]
            result["kick_type"] = rep["kick_type"]
            result["working_source"] = label
            break

    # online mode detection
    if any("online mode" in (k or "").lower() for k in result["kick_texts"]):
        result["online_mode"] = True
        result["kick_type"] = "online_mode"

    # ---- phase 3: real IP subnet scan ----
    need_scan = (result["real_ip"] and not result["joined"]) or args.scan_subnet
    if need_scan:
        log(f"\n=== [3] Real-IP subnet scan (protocol {pvn}) ===")
        try:
            found = await realip_mod.find_real_ip_async(
                host, port, protocol=pvn, timeout=args.timeout,
                scan_subnet=True, workers=args.workers, log=lambda *a: None)
            for f in found:
                if not result["real_ip"]:
                    result["real_ip"] = f["ip"]
                    result["real_ip_source"] = f["via"]
                    log(f"  real IP: {f['ip']}:{f['port']} ({f['via']})")
        except Exception as e:
            log(f"  subnet scan error: {e}")
    else:
        log(f"\n=== [3] Real-IP: skipped (no proxy signal) ===")

    # ---- verdict ----
    if result["joined"] and result["join_game"]:
        result["verdict"] = "JOINED (реально в мире: join_game получен)"
    elif result["joined"]:
        result["verdict"] = "JOINED (play state; соединение живое, keepalive ок)"
    elif result["kick_type"] == "captcha":
        result["verdict"] = f"CAPTCHA: {result['kick']}"
    elif result["kick_type"] == "registration":
        result["verdict"] = f"REGISTRATION: {result['kick']}"
    elif result["kick_type"] == "online_mode":
        result["verdict"] = "ONLINE MODE (нужен аккаунт, cracked не пройдёт)"
    elif result["kick"]:
        result["verdict"] = f"KICK: {result['kick']}"
    else:
        result["verdict"] = "NO SIGNAL (сервер молчит / IP-фильтр / все прокси мертвы)"

    result["elapsed"] = round(time.time() - t_start, 1)

    # ---- print ----
    log("\n" + "=" * 60)
    log("RESULT (JSON)")
    log("=" * 60)
    log(json.dumps(result, ensure_ascii=False, indent=2))

    log("\n--- summary ---")
    log(f"version  : {result['version']} (protocol {result['protocol']})")
    log(f"real IP  : {result['real_ip']} [{result['real_ip_source']}]")
    log(f"joined   : {result['joined']}  join_game={result['join_game']}")
    log(f"keeps    : {result['keeps']}  chats={result['chats']}  respawns={result['respawns']}")
    if result["kick_texts"]:
        log(f"kick(s)  : {result['kick_texts']}")
    log(f"verdict  : {result['verdict']}")
    log(f"(elapsed {result['elapsed']}s)")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        log(f"\nsaved -> {args.out}")


def parse_args():
    ap = argparse.ArgumentParser(description="MC real-player login test")
    ap.add_argument("host")
    ap.add_argument("port", type=int, default=25565, nargs="?")
    ap.add_argument("-v", "--version", help="client version (1.16..26.3) or protocol int; default auto-detect")
    ap.add_argument("--name", default="playtest", help="in-game username")
    ap.add_argument("--stay", type=float, default=20.0, help="seconds to stay in world after join")
    ap.add_argument("--chat", help="custom chat message (default: random)")
    ap.add_argument("--proxy", action="append", help="proxy URL(s), comma separated, repeatable")
    ap.add_argument("--proxy-file", help="file with proxies, one per line")
    ap.add_argument("--fetch", type=int, default=0, help="fetch N free proxies from public lists")
    ap.add_argument("--max-proxies", type=int, default=0, help="cap proxy count")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-probe timeout (status)")
    ap.add_argument("--login-timeout", type=float, default=20.0, help="login/keepalive timeout")
    ap.add_argument("--workers", type=int, default=25)
    ap.add_argument("--scan-subnet", action="store_true", help="force subnet scan for real IP")
    ap.add_argument("--no-direct", action="store_true", help="skip direct connection attempt")
    ap.add_argument("--out", help="save JSON report to file")
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print("\ninterrupted")
