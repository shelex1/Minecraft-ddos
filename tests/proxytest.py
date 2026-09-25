import sys, asyncio
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.mcconn import MCConn
from mcddos.proxies import parse_proxy_line

async def main():
    pr = parse_proxy_line('http://127.0.0.1:3129')
    print('proxy:', pr)
    for port, ver in [(25573, '1.21.1'), (25570, '1.16.5')]:
        c = MCConn('127.0.0.1', port, proxy=pr, username='ptest')
        try:
            info = await c.status(ver)
            v = info.get('version', {}) if info else {}
            print(f"via-proxy status {ver} -> {v.get('name')}")
        except Exception as e:
            print(f"via-proxy status {ver} ERR {type(e).__name__}: {e}")
        finally:
            await c.close()
        # login through proxy
        c = MCConn('127.0.0.1', port, proxy=pr, username='ptest')
        try:
            ok = await asyncio.wait_for(c.login(ver, wait_play=False), 10)
            print(f"via-proxy login {ver} -> {ok} state={c.state}")
        except Exception as e:
            print(f"via-proxy login {ver} ERR {type(e).__name__}: {e}")
        finally:
            await c.close()

asyncio.run(main())
