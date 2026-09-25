import socket, select, time, sys, json
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='CoreLand.go-srv.top'

def probe(P, wait=12, single=False, nodelay=True):
    s=socket.create_connection((HOST,25565),timeout=20)
    if nodelay:
        s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    hs=mc.handshake_payload(P,HOST,25565,2)
    frame=mc.varint(len(hs)+1)+mc.varint(0)+hs
    if single:
        s.sendall(frame+b'\x01\x00')
    else:
        s.sendall(frame)
        time.sleep(0.05)
        s.sendall(b'\x01\x00')
    s.settimeout(4)
    t0=time.time(); buf=b''
    while time.time()-t0 < wait:
        r,_,_=select.select([s],[],[],2)
        if r:
            try: ch=s.recv(65536)
            except Exception as e: s.close(); return f'exc {type(e).__name__}'
            if not ch: s.close(); return 'closed'
            buf+=ch
            if len(buf)>2: break
    s.close()
    if len(buf)>2:
        try:
            b=buf[0]; ln=b&0x7f; sh=7; p1=1
            while b&0x80:
                b=buf[p1]; ln|=(b&0x7f)<<sh; sh+=7; p1+=1
            d=json.loads(buf[p1:p1+ln].decode('utf-8','replace'))
            return 'OK '+str(d.get('version',{}).get('name'))[:50]
        except Exception as e:
            return f'got {len(buf)}B parse {e}'
    return 'silent'

for P in (769, 775, 767, 770):
    print(f'pvn={P} sep  -> {probe(P)}')
    time.sleep(1)
print('pvn=769 single ->', probe(769, single=True))
time.sleep(1)
print('pvn=769 nonodelay ->', probe(769, nodelay=False))
