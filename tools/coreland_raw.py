import socket, select, time, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST=sys.argv[1] if len(sys.argv)>1 else 'CoreLand.go-srv.top'
P=int(sys.argv[2]) if len(sys.argv)>2 else 767
s = socket.create_connection((HOST,25565), timeout=25)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
hs = mc.handshake_payload(P, HOST, 25565, 2)
s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
t0=time.time()
buf=b''
while time.time()-t0 < 30:
    r,_,_=select.select([s],[],[],2)
    if r:
        try: ch=s.recv(65536)
        except Exception as e: print('recv exc',e); break
        if not ch: print('closed'); break
        buf+=ch
        print(f't={time.time()-t0:.1f} +{len(ch)}B cum={len(buf)}')
print('TOTAL', len(buf))
print('hex:', buf.hex()[:400])
# try parse as JSON (status response)
try:
    # varint length then json
    b=buf[0]; ln=b&0x7F; sh=7; p1=1
    while b&0x80:
        b=buf[p1]; ln|=(b&0x7F)<<sh; sh+=7; p1+=1
    j=buf[p1:p1+ln].decode('utf-8','replace')
    import json
    d=json.loads(j)
    print('STATUS JSON:')
    print(' version:', d.get('version'))
    print(' players:', d.get('players',{}).get('online'), '/', d.get('players',{}).get('max'))
    print(' favicon present:', 'icon' in d)
    print(' description:', str(d.get('description'))[:300])
except Exception as e:
    print('json parse:', e)
