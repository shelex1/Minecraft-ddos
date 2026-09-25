import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDS = [
 ("play.cubecraft.net",25565),
 ("eu.hivecp.com",25565),
 ("hypixel.net",25565),
 ("mc.hypixel.net",25565),
 ("play.elypse.cafe",25565),
 ("play.aiden.camp",25565),
 ("play.vortex.camp",25565),
 ("mc.grief.camp",25565),
 ("play.stardust.space",25565),
 ("ru.hivecp.com",25565),
 ("mc.ayrs.ru",25565),
 ("play.ayrs.ru",25565),
 ("eu1.cubecraft.net",25565),
 ("mc.cubecraft.net",25565),
 ("survival.elypse.cafe",25565),
 ("ru.elypse.cafe",25565),
]

async def login(h,p):
    c = MCConn(h,p)
    try:
        st = await asyncio.wait_for(c.status(), 8)
        if not st: return "no-status"
        ver = st.get('version',{}).get('protocol')
        if not ver: return "no-protocol"
        ok = await asyncio.wait_for(c.login(ver, wait_play=False), 10)
        if ok: return f"LOGIN-OK state={c.state}"
        return f"login-fail kick={c.kick_reason} backend={c.real_backend}"
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
        print(f"{h:28} -> {r}")

asyncio.run(main())
