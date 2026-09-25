import asyncio, sys, json
sys.path.insert(0, '.')
from mcddos.mcconn import MCConn

HOST = "CoreLand.go-srv.top"
PORT = 25565

async def try_status(pvn, timeout=12):
    c = MCConn(HOST, PORT, timeout=timeout)
    c.log = lambda *a: None
    try:
        d = await c.status(pvn=pvn)
        return d
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    finally:
        await c.close()

async def try_login(pvn, timeout=16, name="mcddosdetect"):
    c = MCConn(HOST, PORT, timeout=timeout, username=name, online=False)
    c.log = lambda *a: None
    ok = False
    try:
        ok = await c.login(pvn, wait_play=True)
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    return {"ok": ok, "kick": c.kick_reason, "real_backend": c.real_backend, "state": c.state}

async def main():
    print("=== STATUS scan (protocols) ===", flush=True)
    best = None
    for pvn in (775, 774, 773, 772, 771, 770, 769, 768, 767, 765, 764, 763):
        d = await try_status(pvn)
        if isinstance(d, dict):
            v = d.get("version", {})
            players = d.get("players", {})
            print(f"  pvn={pvn}: OK  ver={v.get('name')} proto={v.get('protocol')} players={players.get('online')}/{players.get('max')}", flush=True)
            best = pvn
            break
        else:
            print(f"  pvn={pvn}: {str(d)[:60]}", flush=True)
    print(f"\nBEST status protocol: {best}", flush=True)

    print("\n=== LOGIN attempts ===", flush=True)
    for pvn in ([best] if best else []) + [775, 767, 765]:
        r = await try_login(pvn)
        print(f"  login pvn={pvn}: {json.dumps(r, ensure_ascii=False) if isinstance(r,dict) else r}", flush=True)

asyncio.run(main())
