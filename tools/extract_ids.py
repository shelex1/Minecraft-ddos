import json, os
SRC='/tmp/mcd/node_modules/minecraft-data/minecraft-data/data/pc'

def idx_of(d, state, direction, name):
    try:
        return list(d[state][direction]['types'].keys()).index(name)
    except (ValueError, KeyError, TypeError):
        return None

def find_first(d, state, direction, pred):
    try:
        keys = list(d[state][direction]['types'].keys())
    except (KeyError, TypeError):
        return None, None
    for i, k in enumerate(keys):
        if pred(k, d[state][direction]['types'][k]):
            return i, k
    return None, None

rows = []
for d in sorted(os.listdir(SRC)):
    vj = os.path.join(SRC, d, 'version.json')
    pj = os.path.join(SRC, d, 'protocol.json')
    if not (os.path.exists(vj) and os.path.exists(pj)):
        continue
    v = json.load(open(vj))
    name = v.get('minecraftVersion') or v.get('name') or d
    proto = v.get('version')
    typ = v.get('releaseType') or v.get('type') or 'release'
    if typ != 'release':
        continue
    if proto is None or proto < 735:
        continue
    # skip snapshots/pre/rc by name
    low = d.lower()
    if any(x in low for x in ('-pre', '-rc', '-snapshot')):
        continue
    data = json.load(open(pj))
    # join_game: SpawnInfo preferred
    ji, jn = find_first(data, 'play', 'toClient', lambda k, t: k == 'SpawnInfo')
    # keep_alive
    ki = idx_of(data, 'play', 'toClient', 'packet_keep_alive')
    kis = idx_of(data, 'play', 'toServer', 'packet_keep_alive')
    # ping (S2C) & pong (C2S)
    pi = idx_of(data, 'play', 'toClient', 'packet_ping')
    pong = idx_of(data, 'play', 'toServer', 'packet_pong')
    rows.append({
        'name': name, 'proto': proto, 'join': ji, 'join_name': jn,
        'keep_s2c': ki, 'keep_c2s': kis, 'ping_s2c': pi, 'pong_c2s': pong,
    })

rows.sort(key=lambda r: r['proto'])
print(f"{'name':12} {'proto':>5} {'join':>5} {'keep_s2c':>9} {'keep_c2s':>9} {'ping_s2c':>9} {'pong_c2s':>9}")
for r in rows:
    print(f"{r['name']:12} {r['proto']:>5} {str(r['join']):>5} {str(r['keep_s2c']):>9} {str(r['keep_c2s']):>9} {str(r['ping_s2c']):>9} {str(r['pong_c2s']):>9}")

# Save a clean mapping for patching packets.json
out = {str(r['proto']): {
    'join_game': r['join'], 'keep_alive_s2c': r['keep_s2c'], 'keep_alive_c2s': r['keep_c2s'],
    'ping_s2c': r['ping_s2c'], 'pong_c2s': r['pong_c2s'],
} for r in rows}
json.dump(out, open('mcddos/data/ids_releases.json', 'w'), indent=1)
print('saved ids_releases.json')
