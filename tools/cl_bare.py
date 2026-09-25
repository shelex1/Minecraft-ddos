import socket, select, time, sys
sys.path.insert(0, '.')
from mcddos import protocol as mc

HOST = "CoreLand.go-srv.top"

def bare(wait):
    s = socket.create_connection((HOST, 25565), timeout=15)
    t0=time.time()
    print(f"  bare connect, no data, waiting {wait}s")
    closed=False
    while time.time()-t0 < wait:
        r,_,_ = select.select([s],[],[],2)
        if r:
            try: ch=s.recv(65536)
            except Exception as e:
                print(f"  recv exc {type(e).__name__} at {time.time()-t0:.1f}s"); break
            if not ch:
                print(f"  CLOSED at {time.time()-t0:.1f}s"); closed=True; break
            print(f"  +{len(ch)}B {ch[:60].hex()}")
    if not closed: print(f"  still open after {wait}s")
    s.close()

def single_byte(b, wait):
    s = socket.create_connection((HOST, 25565), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(bytes([b]))
    t0=time.time(); total=0
    while time.time()-t0 < wait:
        r,_,_ = select.select([s],[],[],2)
        if r:
            try: ch=s.recv(65536)
            except Exception as e:
                print(f"  recv exc {type(e).__name__}"); break
            if not ch: print(f"  CLOSED after {time.time()-t0:.1f}s"); break
            total+=len(ch); print(f"  +{len(ch)}B {ch[:60].hex()}")
    print(f"  total {total}B")
    s.close()

print("== bare (no data) =="); bare(12)
print("== single byte 0x00 =="); single_byte(0,8)
print("DONE")
