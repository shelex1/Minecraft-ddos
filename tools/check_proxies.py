"""Check which proxies are alive + their egress IP type (residential?)."""
import asyncio, sys, json
sys.path.insert(0, ".")
import aiohttp
from mcddos.proxies import fetch_proxies

async def main():
    print("fetching 1500 proxies...", flush=True)
    proxies = await fetch_proxies(limit=1500)
    print(f"got {len(proxies)}", flush=True)
    sem = asyncio.Semaphore(50)
    alive = []

    async def check(p, session):
        url = f"{p['type']}://{p['host']}:{p['port']}"
        if p.get("userpass"):
            url = f"{p['type']}://{'%s' % p['userpass']}@{p['host']}:{p['port']}"
        async with sem:
            try:
                async with session.get("https://api.ipify.org?format=json",
                                       proxy=url, timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as r:
                    j = await r.json()
                    ip = j.get("ip")
                    alive.append({"proxy": f"{p['host']}:{p['port']}", "type": p["type"],
                                  "egress": ip, "userpass": p.get("userpass")})
            except Exception:
                pass

    connector = aiohttp.TCPConnector(limit=100, ssl=False)
    headers = {"User-Agent": "Mozilla/5.0"}
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        await asyncio.gather(*(check(p, session) for p in proxies))

    print(f"ALIVE: {len(alive)}")
    # classify egress via ip-api batch
    if alive:
        ips = [a["egress"] for a in alive]
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get("http://ip-api.com/batch?fields=ip,country,org,as,query",
                                       json=ips[:100], timeout=aiohttp.ClientTimeout(total=15)) as r:
                    meta = await r.json()
                    for a, m in zip(alive[:100], meta):
                        if m.get("status") == "success":
                            a["country"] = m.get("country")
                            a["org"] = (m.get("org") or "")[:40]
            except Exception as e:
                print("ip-api err", e)
    with open("alive_proxies.json", "w") as f:
        json.dump(alive, f, indent=1)
    print("saved alive_proxies.json")
    for a in alive[:40]:
        print(f"  {a['proxy']} ({a['type']}) -> {a['egress']} {a.get('country','')} {a.get('org','')}")

asyncio.run(main())
