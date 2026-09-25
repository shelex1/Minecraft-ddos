import sys, asyncio
import os; _r=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, _r)
from mcddos.bots import BotPool

async def wait_join(pool, timeout=20):
    t0 = asyncio.get_event_loop().time()
    while asyncio.get_event_loop().time() - t0 < timeout:
        if all(b.joined for b in pool.bots):
            return True
        await asyncio.sleep(0.3)
    return all(b.joined for b in pool.bots)

async def main():
    for port, ver, wait in [(25572, '1.20.4', 18), (25570, '1.16.5', 18)]:
        pool = BotPool('127.0.0.1', port, ver, count=2, chat_every=3.0,
                       log=lambda *a: print('  LOG', *a))
        pool.spawn(2)
        pool.start_all()
        joined = await wait_join(pool)
        # now hold for `wait` seconds; keepalive should keep them alive
        await asyncio.sleep(wait)
        s = pool.stats()
        ok = s['joined'] == s['total'] and s['kicks'] == 0
        print(f"{ver}: joined_at_start={joined} after {wait}s -> {s}  {'PASS' if ok else 'FAIL'}")
        await pool.stop_all()

asyncio.run(main())
