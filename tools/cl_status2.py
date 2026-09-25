import socket, select, time, json
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='CoreLand.go-srv.top'; P=769
s=socket.create_connection((HOST,25565),timeout=30)
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
hs=mc.handshake_payload(P,HOST,25565,2)
s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
s.sendall(b'\x01\x00')
s.settimeout(15)
t0=time.time(); buf=b''
while time.time()-t0 < 18:
    r,_,_=select.select([s],[],[],3)
    if r:
        ch=s.recv(65536)
        if not ch: break
        buf+=ch
        if len(buf)>2: break
print('P=769 TOTAL', len(buf))
if len(buf)>2:
    b=buf[0]; ln=b&0x7f; sh=7; p1=1
    while b&0x80:
        b=buf[p1]; ln|=(b&0x7f)<<sh; sh+=7; p1+=1
    d=json.loads(buf[p1:p1+ln].decode('utf-8','replace'))
    print('version:', d.get('version'))
    print('players:', d.get('players',{}).get('online'),'/',d.get('players',{}).get('max'))
