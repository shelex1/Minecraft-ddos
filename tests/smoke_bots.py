import sys, asyncio
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.bots import BotPool

async def main():
    for port, ver in [(25570, '1.16.5'), (25573, '1.21.1')]:
        pool = BotPool('127.0.0.1', port, ver, count=3, chat_every=2.0,
                       log=lambda *a: print('LOG', *a))
        pool.spawn(3)
        pool.start_all()
        await asyncio.sleep(6)
        print(f"{ver} -> stats:", pool.stats())
        await pool.stop_all()

asyncio.run(main())
