import sys, asyncio
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.mcconn import MCConn

TESTS = [
    ("hub.pvpg.net", 25565, "1.20.4"),      # hypixel-ish
    ("mc.hypixel.net", 25565, "1.20"),
    ("play.nodecraft.com", 25565, "1.19"),
    ("mc.aurelius.gg", 25565, "1.21"),
]

async def one(host, port, ver):
    c = MCConn(host, port)
    try:
        info = await c.status(ver)
        if info:
            v = info.get("version", {})
            d = info.get("description", "")
            if isinstance(d, dict):
                d = d.get("text", "")
            pl = info.get("players", {})
            print(f"  {host}:{port} ver={v.get('name')} proto={v.get('protocol')} players={pl.get('online')}/{pl.get('max')} motd={str(d)[:40]!r}")
            return True
        print(f"  {host}:{port} NO RESPONSE")
        return False
    except Exception as e:
        print(f"  {host}:{port} ERR {type(e).__name__}: {e}")
        return False
    finally:
        await c.close()

async def main():
    for h, p, v in TESTS:
        await one(h, p, v)

asyncio.run(main())
