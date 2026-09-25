import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDS = [
 ("play.marcus.wtf",25565),
 ("mc.ayrs.ru",25565),
 ("play.ayrs.ru",25565),
 ("ru.ayrs.ru",25565),
 ("play.elypse.cafe",25565),
 ("ru.elypse.cafe",25565),
 ("play.aiden.camp",25565),
 ("mc.aiden.camp",25565),
 ("play.vortex.camp",25565),
 ("mc.vortex.camp",25565),
 ("play.grief.camp",25565),
 ("mc.grief.camp",25565),
 ("play.stardust.space",25565),
 ("ru.hivecp.com",25565),
 ("eu.hivecp.com",25565),
 ("play.cubecraft.net",25565),
]

async def login(h,p):
    c = MCConn(h,p)
    try:
        st = await asyncio.wait_for(c.status(), 7)
        if not st: return "no-status"
        ver = st.get('version',{}).get('protocol')
        if not ver: return "no-protocol"
        ok = await asyncio.wait_for(c.login(ver, wait_play=False), 8)
        if ok: return f"LOGIN-OK state={c.state} ver={ver}"
        return f"login-fail kick={str(c.kick_reason)[:28]} ver={ver}"
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        await c.close()

async def main():
    # run in parallel batches
    sem = asyncio.Semaphore(8)
    async def one(h,p):
        async with sem:
            try:
                r = await asyncio.wait_for(login(h,p), 18)
            except asyncio.TimeoutError:
                r = "TIMEOUT"
            print(f"{h:28} -> {r}", flush=True)
    await asyncio.gather(*[one(h,p) for h,p in CANDS])

asyncio.run(main())
