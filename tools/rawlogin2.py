import socket, os, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
P=int(os.environ.get('P','767'))
s = socket.create_connection(('play.cubecraft.net', 25565), timeout=30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, 'play.cubecraft.net', 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(25)
def rf(s):
    b=b''
    while len(b)<1:
        c=s.recv(1)
        if not c: return None
        b+=c
    ln=b[0]
    while ln & 0x80:
        n=s.recv(1)
        if not n: return None
        ln=(ln<<7)|(n[0]&0x7F)
    body=b''
    while len(body)<ln:
        ch=s.recv(ln-len(body))
        if not ch: break
        body+=ch
    return ln,body
r=rf(s)
ln,body=r
pid=mc.Reader(body,P).read_varint()
print('pid:',pid)
pos=1
l=0;shift=0
while True:
    byte=body[pos];pos+=1
    l|=(byte&0x7F)<<shift
    if not (byte&0x80): break
    shift+=7
txt=body[pos:pos+l].decode('utf-8','replace')
print('KICK REASON (first 2500):')
print(txt[:2500])
