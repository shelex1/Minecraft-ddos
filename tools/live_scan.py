import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDS = [
 ("join.insanitycraft.net",25565),
 ("mc.lumamc.net",25565),
 ("one.lemoncloud.net",25565),
 ("org.earthmc.net",25565),
 ("org.twenture.net",25565),
 ("play.boholmc.net",25565),
 ("top.zetrex.net",25565),
]

async def login(h,p):
    c = MCConn(h,p)
    try:
        st = await asyncio.wait_for(c.status(), 8)
        if not st: return "no-status"
        ver = st.get('version',{}).get('protocol')
        if not ver: return "no-protocol"
        ok = await asyncio.wait_for(c.login(ver, wait_play=True), 10)
        if ok: return f"***PLAY state={c.state} ver={ver} backend={c.real_backend}"
        k = str(c.kick_reason)[:40]
        return f"kick='{k}' ver={ver}"
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        await c.close()

async def main():
    for h,p in CANDS:
        try:
            r = await asyncio.wait_for(login(h,p), 22)
        except asyncio.TimeoutError:
            r = "TIMEOUT"
        print(f"{h:26} -> {r}", flush=True)

asyncio.run(main())
