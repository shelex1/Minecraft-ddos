import os
import json, os
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'node_modules', 'minecraft-data', 'minecraft-data', 'data', 'pc')

# For each release 759..777 find:
#  - play-state packet names containing 'session' or 'Session' (key registration)
#  - whether login_start has signature/uuid fields
rows = {}
for d in sorted(os.listdir(SRC)):
    vj = os.path.join(SRC, d, 'version.json'); pj = os.path.join(SRC, d, 'protocol.json')
    if not (os.path.exists(vj) and os.path.exists(pj)):
        continue
    v = json.load(open(vj)); proto = v.get('version')
    if proto is None or proto < 759:
        continue
    if (v.get('releaseType') or v.get('type')) != 'release':
        continue
    if any(x in d.lower() for x in ('-pre', '-rc', '-snapshot')):
        continue
    data = json.load(open(pj))
    ls = data['login']['toServer']['types'].get('packet_login_start')
    ls_names = [f.get('name') for f in (ls[1] if isinstance(ls, list) else [])]
    # play toServer session packets
    sess = []
    for i, (n, t) in enumerate(data['play']['toServer']['types'].items()):
        if 'session' in n.lower():
            sess.append((i, n))
    rows[proto] = {'ver': d, 'login_start': ls_names, 'play_session': sess}

for p in sorted(rows):
    print(p, rows[p])
