import asyncio, sys, json
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

CANDIDATES = [
    ("hypixel.net", 25565),
    ("play.cubecraft.net", 25565),
    ("eu.hivecp.com", 25565),
    ("mc.ayrs.ru", 25565),
    ("play.elypse.cafe", 25565),
    ("ru.elypse.cafe", 25565),
    ("play.aiden.camp", 25565),
    ("mc.grief.camp", 25565),
    ("play.vortex.camp", 25565),
    ("hypixel.ru", 25565),
    ("play.hypixel.space", 25565),
    ("mc.aiden.camp", 25565),
    ("play.stardust.space", 25565),
    ("eu1.cubecraft.net", 25565),
]

async def status(h,p):
    c = MCConn(h,p)
    try:
        info = await c.status()
        if info:
            v = info.get('version',{})
            pl = info.get('players',{})
            return f"OK ver={v.get('name','?')} p={pl.get('online')}/{pl.get('max')}"
        return "NO-INFO"
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        await c.close()

async def main():
    for h,p in CANDIDATES:
        try:
            r = await asyncio.wait_for(status(h,p), 10)
        except asyncio.TimeoutError:
            r = "TIMEOUT"
        print(f"{h:28} {r}")

asyncio.run(main())
