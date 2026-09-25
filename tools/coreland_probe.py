import socket, select, time, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='CoreLand.go-srv.top'; P=775
WAIT=int(sys.argv[1]) if len(sys.argv)>1 else 60
TRIES=3
for t in range(TRIES):
    try:
        s=socket.create_connection((HOST,25565),timeout=30)
        s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        hs=mc.handshake_payload(P,HOST,25565,2)
        s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
        s.settimeout(5)
        t0=time.time(); got=0
        while time.time()-t0 < WAIT:
            r,_,_=select.select([s],[],[],3)
            if r:
                try: ch=s.recv(65536)
                except Exception as e: print(f'  t{t} recv exc {type(e).__name__}'); break
                if not ch: print(f'  t{t} CLOSED at {time.time()-t0:.0f}s'); break
                got+=len(ch)
                print(f'  t{t} t={time.time()-t0:.0f}s +{len(ch)}B hex={ch[:60].hex()}')
        print(f'  t{t} TOTAL {got}B')
        if got: break
    except Exception as e:
        print(f'  t{t} ERR {type(e).__name__}')
    time.sleep(3)
