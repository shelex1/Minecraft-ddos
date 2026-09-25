import socket, select, time, sys, json
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='CoreLand.go-srv.top'; P=775
s=socket.create_connection((HOST,25565),timeout=30)
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
hs=mc.handshake_payload(P,HOST,25565,2)
s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
# status request: frame len 1, packet id 0
s.sendall(b'\x01\x00')
s.settimeout(20)
t0=time.time(); buf=b''
while time.time()-t0 < 25:
    r,_,_=select.select([s],[],[],3)
    if r:
        try: ch=s.recv(65536)
        except Exception as e: print('recv exc',type(e).__name__); break
        if not ch: print('CLOSED'); break
        buf+=ch
        print(f't={time.time()-t0:.1f}s +{len(ch)}B')
        if len(buf) > 2: break
print('TOTAL', len(buf))
if len(buf) > 2:
    b=buf[0]; ln=b&0x7f; sh=7; p1=1
    while b&0x80:
        b=buf[p1]; ln|=(b&0x7f)<<sh; sh+=7; p1+=1
    j=buf[p1:p1+ln].decode('utf-8','replace')
    try:
        d=json.loads(j)
        print('version:', d.get('version'))
        print('players:', d.get('players',{}).get('online'), '/', d.get('players',{}).get('max'))
        desc=d.get('description','')
        print('motd:', str(desc)[:200])
        print('favicon:', 'yes' if d.get('icon') else 'no')
    except Exception as e:
        print('json err', e); print('raw:', j[:300])
