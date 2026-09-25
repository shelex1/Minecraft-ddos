import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDS = [
 # known cracked / offline networks
 ("mc.voidcraft.net",25565),
 ("play.voidcraft.net",25565),
 ("play.elypse.cafe",25565),
 ("ru.elypse.cafe",25565),
 ("play.aiden.camp",25565),
 ("mc.aiden.camp",25565),
 ("play.vortex.camp",25565),
 ("play.grief.camp",25565),
 ("mc.grief.camp",25565),
 ("play.marcus.wtf",25565),
 ("mc.ayrs.ru",25565),
 ("play.ayrs.ru",25565),
 ("mc.craftmania.ru",25565),
 ("play.craftmania.ru",25565),
 ("play.survivalcraft.net",25565),
 ("survival.marcus.wtf",25565),
 ("mc.purpur.camp",25565),
 ("play.purpur.camp",25565),
 ("mc.banana.cafe",25565),
 ("mc.rustcube.net",25565),
]

async def login(h,p):
    c = MCConn(h,p)
    try:
        st = await asyncio.wait_for(c.status(), 7)
        if not st: return "no-status"
        ver = st.get('version',{}).get('protocol')
        if not ver: return "no-protocol"
        ok = await asyncio.wait_for(c.login(ver, wait_play=True), 9)
        if ok: return f"***PLAY state={c.state} ver={ver} backend={c.real_backend}"
        k = str(c.kick_reason)[:30]
        return f"kick='{k}' ver={ver}"
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        await c.close()

async def main():
    sem = asyncio.Semaphore(10)
    async def one(h,p):
        async with sem:
            try:
                r = await asyncio.wait_for(login(h,p), 17)
            except asyncio.TimeoutError:
                r = "TIMEOUT"
            print(f"{h:26} -> {r}", flush=True)
    await asyncio.gather(*[one(h,p) for h,p in CANDS])

asyncio.run(main())
