import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

async def status(host, port, ver=None):
    c = MCConn(host, port)
    try:
        info = await c.status(ver)
        if info:
            d = info.get('description','')
            if isinstance(d, dict): d = d.get('text','')
            return (f"OK {info.get('version',{}).get('name','?')} players={info.get('players',{}).get('online')}/{info.get('players',{}).get('max')} motd={str(d)[:40]}")
        return "NO-INFO"
    except Exception as e:
        return f"ERR {type(e).__name__}: {str(e)[:40]}"
    finally:
        await c.close()

CANDIDATES = [
    ("hypixel.net", 25565),
    ("minecraft.net", 25565),
    ("play.cubecraft.net", 25565),
    ("eu.hivecp.com", 25565),
    ("mc.hypixel.net", 25565),
    ("survival.marcus.wtf", 25565),
]

async def main():
    for h,p in CANDIDATES:
        r = await asyncio.wait_for(status(h,p), 12)
        print(f"{h}:{p} -> {r}")

asyncio.run(main())
