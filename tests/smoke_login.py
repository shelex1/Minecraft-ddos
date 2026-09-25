import sys, asyncio, traceback
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.mcconn import MCConn

TESTS = [
    (25570, '1.16.5'),
    (25571, '1.19.2'),
    (25572, '1.20.4'),
    (25573, '1.21.1'),
]

async def main():
    for port, ver in TESTS:
        c = MCConn('127.0.0.1', port, username='tester')
        try:
            ok = await asyncio.wait_for(c.login(ver, wait_play=True), timeout=12)
            print(f"{ver} -> login={ok} state={c.state} kick={c.kick_reason}")
            if ok:
                # test chat
                await c.chat('hello from mcddos')
                await asyncio.sleep(0.3)
        except asyncio.TimeoutError:
            print(f"{ver} -> TIMEOUT state={c.state} kick={c.kick_reason}")
        except Exception as e:
            print(f"{ver} -> ERR {type(e).__name__}: {e}")
            traceback.print_exc()
        finally:
            await c.close()

asyncio.run(main())
