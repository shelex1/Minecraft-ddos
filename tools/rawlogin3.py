import socket, os, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
P=int(os.environ.get('P','775'))
s = socket.create_connection(('play.cubecraft.net', 25565), timeout=30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, 'play.cubecraft.net', 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
# login_start per version fields
uuid = b'\x00'*16
ls = mc.varint(0) + mc.str_field('mcddosprobe') + uuid
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(15)
import select
buf=b''
try:
    while len(buf) < 400:
        r,_,_ = select.select([s],[],[],12)
        if not r: 
            print('select timeout, got so far:', buf[:40].hex())
            break
        ch = s.recv(4096)
        if not ch: break
        buf += ch
        if len(buf) > 2: break  # stop after first chunk
except Exception as e:
    print('recv err', e)
print('RAW first bytes:', buf[:60].hex())
print('len:', len(buf))
