import json, os
SRC='/tmp/mcd/node_modules/minecraft-data/minecraft-data/data/pc'

def idx(keys, name):
    try:
        return keys.index(name)
    except ValueError:
        return None

def find_join(data):
    keys = list(data['play']['toClient']['types'].keys())
    # SpawnInfo (1.20.5+)
    for i, k in enumerate(keys):
        if k == 'SpawnInfo':
            return i, k
    # legacy join_game: first play->client packet with hashedSeed + gamemode/gameMode + entityId
    for i, k in enumerate(keys):
        t = data['play']['toClient']['types'][k]
        if isinstance(t, list) and t and t[0] == 'container' and isinstance(t[1], list):
            names = [f.get('name') for f in t[1] if isinstance(f, dict)]
            if 'hashedSeed' in names and ('gamemode' in names or 'gameMode' in names) and ('entityId' in names or 'dimension' in names):
                return i, k
    return None, None

# build version name -> pvn from version.json (authoritative for THIS data source)
ver2pvn = {}
for d in sorted(os.listdir(SRC)):
    vj = os.path.join(SRC, d, 'version.json')
    pj = os.path.join(SRC, d, 'protocol.json')
    if not (os.path.exists(vj) and os.path.exists(pj)):
        continue
    v = json.load(open(vj))
    pvn = v.get('version')
    if pvn is None or pvn < 735 or pvn > 800:
        continue
    data = json.load(open(pj))
    if 'play' not in data:
        continue
    pc = list(data['play']['toClient']['types'].keys())
    ps = list(data['play']['toServer']['types'].keys())
    ji, jn = find_join(data)
    ver2pvn[d] = {
        'pvn': pvn,
        'join_game': ji,
        'join_name': jn,
        'keep_alive_s2c': idx(pc, 'packet_keep_alive'),
        'keep_alive_c2s': idx(ps, 'packet_keep_alive'),
        'ping_s2c': idx(pc, 'packet_ping'),
        'pong_c2s': idx(ps, 'packet_pong'),
        'respawn': idx(pc, 'packet_respawn'),
    }

# now patch packets.json for every pvn present
data = json.load(open('mcddos/data/packets.json'))
# pick the "highest version" per pvn? No — each pvn maps to exactly one dir in this dataset mostly.
# Build pvn -> record (prefer the dir whose pvn equals exactly; if multiple, keep first)
pvn2rec = {}
for d, r in ver2pvn.items():
    pvn = str(r['pvn'])
    if pvn not in pvn2rec:
        pvn2rec[pvn] = (d, r)

patched = 0
for pvn in sorted(data.keys(), key=int):
    if pvn in pvn2rec:
        d, r = pvn2rec[pvn]
        rec = data[pvn]
        for field in ('join_game','keep_alive_s2c','keep_alive_c2s','ping_s2c','pong_c2s','respawn'):
            newv = r[field]
            if newv is not None and rec.get(field) != newv:
                old = rec.get(field)
                rec[field] = newv
                patched += 1
                print(f'pvn {pvn} ({d}) {field}: {old} -> {newv}')
    else:
        print(f'pvn {pvn}: no dir match (kept existing)')
json.dump(data, open('mcddos/data/packets.json','w'), indent=1)
print('total patched fields:', patched)
print('sample:')
for pvn in ['735','754','759','760','761','764','765','766','767','777']:
    r=data[pvn]
    print(pvn,'join=',r.get('join_game'),'keep_s2c=',r.get('keep_alive_s2c'),'ping_s2c=',r.get('ping_s2c'),'pong=',r.get('pong_c2s'))
