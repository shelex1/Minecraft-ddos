import json, os
SRC='node_modules/minecraft-data/minecraft-data/data/pc'

def get_mappings(d, state, direction):
    try:
        pkt = d[state][direction]['types']['packet']
    except (KeyError, TypeError):
        return None
    # pkt = ['container', [ {name:'name', type:['mapper', {type:'varint', mappings:{...}}]}, {name:'params',...} ]]
    for f in pkt[1]:
        if f.get('name') == 'name':
            t = f.get('type')
            if isinstance(t, list) and t and t[0] == 'mapper':
                return t[1].get('mappings', {})
    return None

def name_to_id(mappings):
    out = {}
    for k, v in mappings.items():
        # k like '0x00' or '0x24'
        try:
            if k.startswith('0x'):
                out[v] = int(k, 16)
            else:
                out[v] = int(k)
        except ValueError:
            pass
    return out

def find_join(data, direction):
    m = get_mappings(data, 'play', direction) or {}
    for name, pid in m.items():
        if name in ('SpawnInfo', 'join_game', 'login'):
            return name, pid
    return None, None

rows = []
for dname in sorted(os.listdir(SRC)):
    pj = os.path.join(SRC, dname, 'protocol.json')
    if not os.path.exists(pj):
        continue
    d = json.load(open(pj))
    if 'play' not in d:
        continue
    vj = os.path.join(SRC, dname, 'version.json')
    pvn = json.load(open(vj)).get('version') if os.path.exists(vj) else None
    m_s2c = name_to_id(get_mappings(d, 'play', 'toClient') or {})
    m_c2s = name_to_id(get_mappings(d, 'play', 'toServer') or {})
    rows.append({
        'dir': dname, 'pvn': pvn,
        'join_game': m_s2c.get('SpawnInfo', m_s2c.get('join_game', m_s2c.get('login'))),
        'keep_alive_s2c': m_s2c.get('keep_alive'),
        'keep_alive_c2s': m_c2s.get('keep_alive'),
        'ping_s2c': m_s2c.get('ping'),
        'pong_c2s': m_c2s.get('pong'),
        'respawn': m_s2c.get('respawn'),
    })

rows.sort(key=lambda r: (r['pvn'] or 0))
print(f"{'dir':10} {'pvn':>4} {'join':>4} {'ka_s2c':>6} {'ka_c2s':>6} {'ping':>5} {'pong':>5} {'resp':>4}")
for r in rows:
    print(f"{r['dir']:10} {str(r['pvn']):>4} {str(r['join_game']):>4} {str(r['keep_alive_s2c']):>6} {str(r['keep_alive_c2s']):>6} {str(r['ping_s2c']):>5} {str(r['pong_c2s']):>5} {str(r['respawn']):>4}")

# Save pvn -> ids
out = {}
for r in rows:
    if r['pvn']:
        out[str(r['pvn'])] = {k: r[k] for k in ('join_game','keep_alive_s2c','keep_alive_c2s','ping_s2c','pong_c2s','respawn')}
json.dump(out, open('mcddos/data/ids_final.json','w'), indent=1)
print('saved ids_final.json, versions:', len(out))
