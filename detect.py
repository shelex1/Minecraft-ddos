#!/usr/bin/env python3
"""
Авто-детект Minecraft-сервера (версия + реальный IP + капча/регистрация)
========================================================================
Самодостателен: использует локальный пакет `mcddos` (MCConn, protocol, proxies).

По host:port скрипт:
  0. резолвит DNS / проверяет TCP
  1. САМ определят протокольную версию (status sweep, напрямую и через прокси)
  2. находит РЕАЛЬНЫЙ IP бэкенда (bungee/velocity prelogin во время login)
  3. определяет требование КАПЧИ / РЕГИСТРАЦИИ (по тексту кика)

Прокси:
  --proxy http://ip:port           (можно несколько, или через запятую)
  --proxy-file proxies.txt         (по одному в строке, синтаксис как у mcddos)
  --fetch 300                      (скачать 300 бесплатных прокси с публичных списков)

Пример:
  venv/bin/python detect.py CoreLand.go-srv.top 25565 --fetch 300 --timeout 4
"""
import argparse
import os
import asyncio
import json
import re
import socket
import sys
import time

#  позволяем запуск из любого каталога (пакет может лежать на уровень выше)
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE), os.getcwd()):
    if os.path.isdir(os.path.join(_p, "mcddos")):
        sys.path.insert(0, _p)
        break
from mcddos.versions import VERSIONS, guess_version_for_protocol   # noqa: E402
from mcddos.mcconn import MCConn                                   # noqa: E402
from mcddos.proxies import parse_proxy_line, fetch_proxies         # noqa: E402

#  протоколы для перебора; наиболее вероятные первыми. Полный набор 735..777.
ALL_PROTOCOLS = [775, 774, 773, 772, 771, 770, 769, 768, 767, 766, 765,
                 764, 763, 762, 761, 760, 759, 758, 757, 756, 755, 754,
                 753, 751, 735]
LIKELY = [775, 774, 773, 772, 771, 767, 765, 763, 760]

CAPTCHA_HINTS = ["капча", "captcha", "recaptcha", "hcaptcha", "geetest",
                 "datadome", "turnstile", "cloudflare"]
REG_HINTS = ["регистрац", "register", "/reg", "sign up", "authme", "register your"]


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------------------
#  пробы
# ---------------------------------------------------------------------------
async def status_probe(host, port, pvn, timeout, proxy=None):
    c = MCConn(host, port, timeout=timeout, proxy=proxy)
    c.log = lambda *a: None
    try:
        return await c.status(pvn=pvn)
    except Exception:
        return None
    finally:
        await c.close()


async def login_probe(host, port, pvn, timeout, proxy=None, name="mcddosdetect"):
    c = MCConn(host, port, timeout=timeout, proxy=proxy, username=name,
               online=False)
    c.log = lambda *a: None
    out = {"ok": False, "kick": None, "backend": None, "state": None, "err": None}
    try:
        out["ok"] = bool(await c.login(pvn, wait_play=True))
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
    out["kick"] = c.kick_reason
    out["backend"] = c.real_backend
    out["state"] = c.state
    try:
        await c.close()
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
#  классификация
# ---------------------------------------------------------------------------
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
                            "offline")):
        return "online_mode"
    return "other"


def version_from_text(text):
    """Достаёт версию MC из текста кика -> protocol."""
    for m in re.finditer(r"(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)", text or ""):
        v = m.group(1)
        if v in VERSIONS:
            return v, VERSIONS[v]
    return None


# ---------------------------------------------------------------------------
#  main (точка входа)
# ---------------------------------------------------------------------------
async def amain(args):
    host, port = args.host, args.port
    result = {
        "host": host, "port": port, "username": args.name,
        "dns": {}, "protocol": None, "version": None, "status": None,
        "real_ip": None, "real_ip_source": None,
        "captcha": None, "working_proxy": None, "notes": [],
    }

    #  ---- фаза 0: DNS ----
    log(f"\n=== [0] DNS :: {host}:{port} ===")
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        result["dns"]["ips"] = ips
        log(f"  A: {ips}")
    except Exception as e:
        result["dns"]["error"] = f"{type(e).__name__}: {e}"
        log(f"  DNS error: {e}")

    try:
        s = socket.create_connection((host, port), timeout=8)
        s.close()
        result["dns"]["tcp"] = "open"
    except Exception as e:
        result["dns"]["tcp"] = f"closed ({type(e).__name__})"
        log(f"  TCP {port}: closed")

    #  ---- собираем список источников прокси ----
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
        t0 = time.time()
        got = await fetch_proxies(limit=args.fetch)
        for p in got:
            add_p(p)
        log(f"  +{len(got)} in {time.time()-t0:.0f}s (unique total {len(proxies)})")
    if args.max_proxies:
        proxies = proxies[:args.max_proxies]

    sources = []
    if args.direct:
        sources.append(("direct", None))
    for p in proxies:
        sources.append((f"proxy {p['host']}:{p['port']} ({p['type']})", p))
    log(f"\n  sources: {len(sources)} (1 direct + {len(proxies)} proxies)")

    #  ---- фаза 1: авто-детект версии (status sweep) ----
    log(f"\n=== [1] Version auto-detect (status sweep, timeout {args.timeout}s) ===")
    if args.protocols:
        protocols = [int(x) for x in args.protocols.split(",")]
    else:
        protocols = LIKELY

    #  этап A: быстрый sweep по `protocols` (по умолчанию LIKELY) для всех источников
    sem = asyncio.Semaphore(args.workers)
    hit = {"r": None}
    done = 0
    total = len(sources) * len(protocols)

    async def try_status(src, pvn):
        nonlocal done
        label, proxy = src
        async with sem:
            d = await status_probe(host, port, pvn, args.timeout, proxy)
        done += 1
        if isinstance(d, dict) and not hit["r"]:
            hit["r"] = (label, proxy, pvn, d)
            log(f"  [~{done}/{total}] STATUS via {label}: pvn={pvn} "
                f"ver={d.get('version',{}).get('name')}")

    t0 = time.time()
    await asyncio.gather(*(try_status(s, p) for s in sources for p in protocols))
    log(f"  stage A: {done} probes in {time.time()-t0:.0f}s")

    if hit["r"]:
        label, proxy, pvn, d = hit["r"]
        v = d.get("version", {})
        result["protocol"] = pvn
        result["version"] = v.get("name") or guess_version_for_protocol(pvn)
        result["working_proxy"] = label
        result["status"] = {
            "version": v,
            "players": d.get("players", {}),
            "motd": str(d.get("description", ""))[:200],
        }
        log(f"  -> version {result['version']} (protocol {pvn}) via {label}")
        log(f"     players {d.get('players',{}).get('online')}/"
            f"{d.get('players',{}).get('max')}")
        log(f"     motd: {str(d.get('description',''))[:120]}")

        #  этап B: точное подтверждение protocol через рабочий источник
        #  (status одинаков для всех совместимых протоколов; лишь убедимся, что
        #   подтверждён максимальный protocol, который сервер указывает как max)
        max_p = int(v.get("protocol", pvn))
        if max_p in ALL_PROTOCOLS and max_p != pvn:
            d2 = await status_probe(host, port, max_p, args.timeout, proxy)
            if isinstance(d2, dict):
                result["protocol"] = max_p
                result["version"] = d2.get("version", {}).get("name") or result["version"]
                log(f"  -> confirmed exact protocol {max_p} ({result['version']})")
        result["notes"].append(f"status via {label}")
    else:
        result["notes"].append("status: no source answered (proxy buffering this IP / dead proxies)")

    #  ---- фазы 2+3: login через рабочий источник (реальный IP + капча) ----
    log("\n=== [2] Login -> real IP (prelogin) + [3] captcha/registration ===")
    login_src = None
    if hit["r"]:
        login_src = hit["r"]
    login_pvn = result["protocol"] or (hit["r"][2] if hit["r"] else 775)

    attempts = []
    #  основной: рабочий источник
    if login_src:
        label, proxy = login_src[0], login_src[1]   # форма: hit["r"] = (label, proxy, pvn, status)
        log(f"  login via {label} pvn={login_pvn} ...")
        info = await login_probe(host, port, login_pvn, args.login_timeout, proxy, args.name)
        attempts.append((label, info))
        _apply_login(result, info, label)
        if info["ok"] or (info["kick"] and classify_kick(info["kick"]) in
                         ("captcha", "registration")):
            pass  # сигнала достаточно
        else:
            #  пробуем и на протоколе старше (некоторые прокси пропускают login только для старых pvn)
            alt = 767 if login_pvn != 767 else 775
            log(f"  login via {label} pvn={alt} (fallback) ...")
            info2 = await login_probe(host, port, alt, args.login_timeout, proxy, args.name)
            attempts.append((label, info2))
            _apply_login(result, info2, label)

    #  вторичный: прямой login (сервер может отвечать напрямую, даже если status закрыт)
    if args.direct and not (result["real_ip"] or result["captcha"]):
        log(f"  login direct pvn={login_pvn} ...")
        info = await login_probe(host, port, login_pvn, args.login_timeout, None, args.name)
        attempts.append(("direct", info))
        _apply_login(result, info, "direct")

    #  третичный: короткий login-sweep через прокси, поймать ЛЮБОЙ текст кика
    cap_score = (result.get("captcha") or {}).get("_score", 0)
    if cap_score < 2 and proxies:
        log(f"\n  login sweep via {min(len(proxies), args.max_login_proxies)} proxies ...")
        sem2 = asyncio.Semaphore(args.workers)
        kicks = []
        total2 = min(len(proxies), args.max_login_proxies) * len(LIKELY[:3])
        done2 = 0

        async def try_login(src, pvn):
            nonlocal done2
            label, proxy = src
            async with sem2:
                info = await login_probe(host, port, pvn, args.timeout, proxy, args.name)
            done2 += 1
            kick = info.get("kick")
            if kick or info.get("ok") or info.get("backend"):
                if done2 % 50 == 0 or kick or info.get("ok"):
                    log(f"  [~{done2}/{total2}] {label} pvn={pvn} ok={info.get('ok')} kick={kick!r} backend={info.get('backend')}")
                kicks.append((label, pvn, info))

        await asyncio.gather(
            *(try_login(s, p) for s in sources[1:1 + args.max_login_proxies]
              for p in LIKELY[:3]))
        log(f"  login sweep: {done2} probes, {len(kicks)} with signal")
        #  лучший сигнал: капча/регистрация > бэкенд > любой кик
        order = {"captcha": 3, "registration": 2, "wrong_version": 1, "other": 0}
        kicks.sort(key=lambda x: (
            order.get(classify_kick(x[2].get("kick")) or "other", 0),
            1 if x[2].get("backend") else 0,
            1 if x[2].get("ok") else 0,
        ), reverse=True)
        if kicks:
            label, pvn, info = kicks[0]
            log(f"  best: {label} pvn={pvn} -> {info}")
            _apply_login(result, info, label)
        result["login_sweep_signal"] = len(kicks)

    #  ---- финализация ----
    log("\n=== RESULT ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    log("\n--- summary ---")
    log(f"version : {result['version']} (protocol {result['protocol']})")
    log(f"real IP : {result['real_ip']} [{result['real_ip_source']}]")
    cap = result.get("captcha") or {}
    log(f"captcha : {cap.get('type')} :: {cap.get('message')}")
    log(f"proxy   : {result['working_proxy']}")
    for n in result["notes"]:
        log(f"  note: {n}")


def _apply_login(result, info, label):
    """Сливает результаты login-проб в результат, оставляя самый сильный сигнал."""
    kick = info.get("kick")
    backend = info.get("backend")
    kind = classify_kick(kick)
    #  реальный IP
    if backend and not result["real_ip"]:
        ip, rport, bkind = backend
        result["real_ip"] = ip
        result["real_ip_source"] = f"{bkind}:pre_login:{rport} via {label}"
        result["notes"].append(f"prelogin via {label}: {ip}:{rport} ({bkind})")
    #  версия из текста кика
    if result["version"] is None and kind == "wrong_version":
        v = version_from_text(kick)
        if v:
            result["version"], result["protocol"] = v
            result["notes"].append(f"version from kick text: {v}")
    #  сигнал капчи (больше = сильнее)
    if info.get("ok"):
        score = 5
    elif kind == "captcha":
        score = 4
    elif kind == "registration":
        score = 3
    elif kick:
        score = 2
    else:
        score = 1  # таймаут / тишина (заблокировано ещё до сервера)
    cur = (result.get("captcha") or {}).get("_score", 0)
    if score > cur:
        if info.get("ok"):
            result["captcha"] = {"type": "none", "message": "reached play state (no captcha gate)",
                                 "_score": 4}
        elif kick:
            result["captcha"] = {"type": kind, "message": kick, "via": label, "_score": score}
        else:
            result["captcha"] = {"type": "timeout",
                                 "message": info.get("err") or "no packet before timeout",
                                 "via": label, "_score": 1}
    if kick and "kick_texts" not in result:
        result["kick_texts"] = []
    if kick and result.get("kick_texts") is not None and kick not in result["kick_texts"]:
        result["kick_texts"].append(kick)


def parse_args():
    ap = argparse.ArgumentParser(description="MC auto-detect: version + real IP + captcha")
    ap.add_argument("host")
    ap.add_argument("port", type=int, default=25565, nargs="?")
    ap.add_argument("--name", default="mcddosdetect")
    ap.add_argument("--proxy", action="append",
                    help="proxy URL(s), comma separated, repeatable")
    ap.add_argument("--proxy-file", help="file with proxies, one per line")
    ap.add_argument("--fetch", type=int, default=0,
                    help="fetch N free proxies from public lists")
    ap.add_argument("--max-proxies", type=int, default=0, help="cap proxy count")
    ap.add_argument("--protocols", help="comma list of protocols to sweep")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-probe timeout")
    ap.add_argument("--login-timeout", type=float, default=20.0)
    ap.add_argument("--workers", type=int, default=25)
    ap.add_argument("--max-login-proxies", type=int, default=150)
    ap.add_argument("--no-direct", dest="direct", action="store_false",
                    help="skip direct connection attempt")
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    t0 = time.time()
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print("\ninterrupted")
    log(f"\n(elapsed {time.time()-t0:.0f}s)")
