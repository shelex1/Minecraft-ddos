import json, os
SRC = '/home/agent/work/mcddos/node_modules/minecraft-data/minecraft-data/data/pc'

if not os.path.isdir(SRC):
    print('SRC not found:', SRC)
    raise SystemExit(1)

def idx_of(d, state, direction, name):
    try:
        return list(d[state][direction]['types'].keys()).index(name)
    except (ValueError, KeyError, TypeError):
        return None

rows = {}
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
    low = d.lower()
    if any(x in low for x in ('-pre', '-rc', '-snapshot')):
        continue
    data = json.load(open(pj))
    cp_c = None  # play custom_payload toClient (s2c)
    cp_s = None  # play custom_payload toServer (c2s)
    for nm in ('packet_custom_payload', 'custom_payload'):
        cp_c = idx_of(data, 'play', 'toClient', nm)
        cp_s = idx_of(data, 'play', 'toServer', nm)
        if cp_c is not None or cp_s is not None:
            break
    conf_c = None
    conf_s = None
    if 'configuration' in data:
        for nm in ('packet_custom_payload', 'custom_payload'):
            conf_c = idx_of(data, 'configuration', 'toClient', nm)
            conf_s = idx_of(data, 'configuration', 'toServer', nm)
            if conf_c is not None or conf_s is not None:
                break
    rows[proto] = {'name': name, 'play_s2c': cp_c, 'play_c2s': cp_s,
                   'conf_s2c': conf_c, 'conf_c2s': conf_s}

for p in sorted(rows):
    print(p, rows[p])
