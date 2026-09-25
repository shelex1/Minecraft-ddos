import socket, sys, struct, time
sys.path.insert(0,'.')
from mcddos import protocol as mc

def varint(v): return mc.varint(v)
def rf(s):
    # read one framed packet
    b = b''
    while len(b) < 1:
        b += s.recv(1)
        if not b: break
    ln = b[0]
    while ln & 0x80:
        n = s.recv(1)
        if not n: return None
        ln = (ln << 7) | (n[0] & 0x7F)
    body = b''
    while len(body) < ln:
        chunk = s.recv(ln - len(body))
        if not chunk: break
        body += chunk
    return ln, body

s = socket.create_connection(('play.cubecraft.net', 25565), timeout=30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
import os
P = int(os.environ.get('P','765'))
hs = mc.handshake_payload(P, 'play.cubecraft.net', 25565, 2)
s.sendall(varint(len(hs)+1) + varint(0) + hs)
import os
P = int(os.environ.get('P','765'))
# login_start: username + playerUUID(16) [+ signature option for 1.19.1-1.19.2]
ls = varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
if P in (759, 760):  # 1.19/1.19.2: signature option BEFORE uuid? no - after uuid
    pass
s.sendall(varint(len(ls)) + ls)
s.settimeout(25)
try:
    for i in range(6):
        r = rf(s)
        if r is None:
            print(f'[{i}] CONN CLOSED')
            break
        ln, body = r
        r2 = mc.Reader(body, P)
        pid = r2.read_varint()
        print(f'[{i}] frame_len={ln} pid={pid} body={body[:60]!r}')
        if pid == 0x04:
            # login_plugin_request: msg_id varint, channel string
            mid = r2.read_varint()
            ch = r2.read_string()
            rest = body[r2.pos:]
            print(f'   plugin_req id={mid} channel={ch} rest={rest[:80]!r}')
            # reply success
            resp = varint(mid) + varint(1)
            s.sendall(varint(2) + varint(len(resp)) + resp)  # login_plugin_resp id=2
            continue
        if pid == 0x03:
            thr = r2.read_varint()
            print('   compression threshold', thr)
            break
        if pid == 0x00:
            try:
                r3 = mc.Reader(body, P)
                msg = r3.read_string()
                print('   DISCONNECT:', msg[:200])
            except Exception as e:
                print('   disconnect parse err', e)
            break
        if pid == 0x02:
            try:
                uuid = body[:16].hex()
                nm = mc.Reader(body[16:],P).read_string()
                print('   LOGIN SUCCESS uuid=', uuid, 'name=', nm)
            except Exception as e:
                print('   success parse', e)
            break
        if pid == 0x01:
            print('   ENCRYPTION BEGIN (online mode)')
            break
except socket.timeout:
    print('TIMEOUT waiting for next packet')
s.close()
