import socket, select, time, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='CoreLand.go-srv.top'
P=int(sys.argv[1]) if len(sys.argv)>1 else 771
WAIT=int(sys.argv[2]) if len(sys.argv)>2 else 35
s = socket.create_connection((HOST,25565), timeout=25)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
hs = mc.handshake_payload(P, HOST, 25565, 2)
s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
t0=time.time()
buf=b''
while time.time()-t0 < WAIT:
    r,_,_=select.select([s],[],[],2)
    if r:
        try: ch=s.recv(65536)
        except Exception as e: print('recv exc',e); break
        if not ch: print('closed'); break
        buf+=ch
        print(f'pvn={P} t={time.time()-t0:.1f} +{len(ch)}B')
print('TOTAL', len(buf), 'hex:', buf.hex()[:200])
