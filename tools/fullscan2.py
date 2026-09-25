import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDS = [
 ("play.rustcube.net",25565),
 ("mc.rustcube.net",25565),
 ("ru.rustcube.net",25565),
 ("play.fabric.camp",25565),
 ("play.vanillagame.net",25565),
 ("vanilla.camp",25565),
 ("play.voidcraft.net",25565),
 ("mc.craftmania.ru",25565),
 ("play.survivalcraft.net",25565),
 ("mc.marcus.wtf",25565),
 ("play.grief.camp",25565),
 ("mc.aiden.camp",25565),
 ("play.sky.camp",25565),
 ("mc.banana.camp",25565),
 ("play.purpur.camp",25565),
 ("mc.purpur.camp",25565),
 ("play.paper.camp",25565),
 ("eu.hivecp.com",25565),
]

async def login(h,p):
    c = MCConn(h,p)
    try:
        st = await asyncio.wait_for(c.status(), 8)
        if not st: return "no-status"
        ver = st.get('version',{}).get('protocol')
        if not ver: return "no-protocol"
        ok = await asyncio.wait_for(c.login(ver, wait_play=False), 9)
        if ok: return f"LOGIN-OK state={c.state} ver={ver}"
        return f"login-fail kick={str(c.kick_reason)[:30]} ver={ver}"
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        await c.close()

async def main():
    for h,p in CANDS:
        try:
            r = await asyncio.wait_for(login(h,p), 20)
        except asyncio.TimeoutError:
            r = "TIMEOUT"
        print(f"{h:28} -> {r}")

asyncio.run(main())
