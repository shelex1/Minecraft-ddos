import asyncio, sys
sys.path.insert(0,'.')
from mcddos.mcconn import MCConn

async def main():
    c = MCConn('top.zetrex.net', 25565, username='mcddos', log=lambda *a: print('  [log]', *a))
    try:
        ok = await asyncio.wait_for(c.login('1.21.1', wait_play=True), 25)
        print('LOGIN:', ok, 'state:', c.state, 'kick:', c.kick_reason, 'backend:', c.real_backend)
        # if in play, try chat
        if ok:
            r = await c.chat('hello from mcddos!')
            print('chat sent:', r)
            await asyncio.sleep(1)
    except Exception as e:
        print('ERR', type(e).__name__, e)
    finally:
        await c.close()

asyncio.run(main())
