import json, os
SRC='/tmp/mcd/node_modules/minecraft-data/minecraft-data/data/pc'
# List all dirs that have version.json and protocol.json, collect name+protocol+type
rows=[]
for d in sorted(os.listdir(SRC)):
    vj=os.path.join(SRC,d,'version.json')
    pj=os.path.join(SRC,d,'protocol.json')
    if not (os.path.exists(vj) and os.path.exists(pj)):
        continue
    v=json.load(open(vj))
    name=v.get('name') or d
    # protocol number
    proto=None
    mv=v.get('minecraft_version')
    if isinstance(mv,dict):
        proto=mv.get('protocol_version')
    if proto is None:
        # read from protocol.json? not there. Use version.json 'type'
        proto=None
    typ=v.get('type')  # 'release','snapshot'
    rows.append((name,d,proto,typ))

# print releases only
print("RELEASES (name, dir, protocol, type):")
for name,d,proto,typ in rows:
    if typ=='release':
        print(f"{name:12} {d:14} {proto} {typ}")
