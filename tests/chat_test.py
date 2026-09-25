import sys, asyncio
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.mcconn import MCConn

async def test(port, ver, n=3):
    c = MCConn('127.0.0.1', port, username='chatter')
    try:
        ok = await asyncio.wait_for(c.login(ver, wait_play=True), 10)
        if not ok:
            print(f"{ver}: login FAIL state={c.state} kick={c.kick_reason}")
            return
        # chat several times
        for i in range(n):
            r = await c.chat(f"hello {ver} msg {i}")
        # read a bit to see if kicked
        try:
            pid, payload = await asyncio.wait_for(c.read_one(), 3)
            print(f"{ver}: chat ok x{n}, next pid={pid} state={c.state}")
        except asyncio.TimeoutError:
            print(f"{ver}: chat ok x{n}, no kick (silent) state={c.state}")
    except Exception as e:
        print(f"{ver}: ERR {type(e).__name__}: {e}")
    finally:
        await c.close()

async def main():
    for port, ver in [(25570,'1.16.5'),(25571,'1.19.2'),(25572,'1.20.4'),(25573,'1.21.1')]:
        await test(port, ver)

asyncio.run(main())
