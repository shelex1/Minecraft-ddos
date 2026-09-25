import json, os, sys
SRC='node_modules/minecraft-data/minecraft-data/data/pc'

def idx(keys, name):
    try:
        return keys.index(name)
    except ValueError:
        return None

def find_join(data):
    keys = list(data['play']['toClient']['types'].keys())
    for i, k in enumerate(keys):
        t = data['play']['toClient']['types'][k]
        if Array := (isinstance(t, list) and t and t[0] == 'container' and isinstance(t[1], list)):
            names = [f.get('name') for f in t[1] if isinstance(f, dict)]
            if 'hashedSeed' in names and ('gamemode' in names or 'gameMode' in names):
                return i, k
    return None, None

rows = []
for d in sorted(os.listdir(SRC)):
    pj = os.path.join(SRC, d, 'protocol.json')
    if not os.path.exists(pj):
        continue
    data = json.load(open(pj))
    if 'play' not in data:
        continue
    pc_keys = list(data['play']['toClient']['types'].keys())
    ps_keys = list(data['play']['toServer']['types'].keys())
    ji, jn = find_join(data)
    rows.append({
        'dir': d,
        'join': ji, 'join_name': jn,
        'keep_s2c': idx(pc_keys, 'packet_keep_alive'),
        'ping_s2c': idx(pc_keys, 'packet_ping'),
        'keep_c2s': idx(ps_keys, 'packet_keep_alive'),
        'pong_c2s': idx(ps_keys, 'packet_pong'),
        'respawn': idx(pc_keys, 'packet_respawn'),
    })

rows.sort(key=lambda r: r['dir'])
print(f"{'dir':10} {'join':>4} {'keep_s2c':>9} {'keep_c2s':>9} {'ping_s2c':>9} {'pong_c2s':>9} {'respawn':>8}")
for r in rows:
    print(f"{r['dir']:10} {str(r['join']):>4} {str(r['keep_s2c']):>9} {str(r['keep_c2s']):>9} {str(r['ping_s2c']):>9} {str(r['pong_c2s']):>9} {str(r['respawn']):>8}")

# save name->ids for the ones we care about
out = {}
for r in rows:
    out[r['dir']] = {k: r[k] for k in ('join','join_name','keep_s2c','keep_c2s','ping_s2c','pong_c2s','respawn')}
json.dump(out, open('mcddos/data/ids_by_dir.json','w'), indent=1)
print('saved ids_by_dir.json')
