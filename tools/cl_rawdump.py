import socket, select, time, sys
sys.path.insert(0, '.')
from mcddos import protocol as mc

HOST = "CoreLand.go-srv.top"
PORT = 25565
WAIT = int(sys.argv[1]) if len(sys.argv) > 1 else 30

def do(pvn, send_status_req=True, send_login=False, name="rawdump"):
    s = socket.create_connection((HOST, PORT), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    hs = mc.handshake_payload(pvn, HOST, PORT, 2 if send_login else 1)
    s.sendall(mc.varint(len(hs) + 1) + mc.varint(0) + hs)
    time.sleep(0.2)
    if send_status_req:
        s.sendall(b"\x01\x00")
    if send_login:
        ls = mc.varint(0) + mc.str_field(name) + b"\x00" * 16
        s.sendall(mc.varint(len(ls)) + ls)
    s.settimeout(5)
    t0 = time.time()
    total = 0
    while time.time() - t0 < WAIT:
        r, _, _ = select.select([s], [], [], 2)
        if r:
            try:
                ch = s.recv(65536)
            except Exception as e:
                print(f"  [{pvn}] recv exc {type(e).__name__}")
                break
            if not ch:
                print(f"  [{pvn}] CLOSED at {time.time()-t0:.1f}s after {total}B")
                break
            total += len(ch)
            print(f"  [{pvn}] t={time.time()-t0:.1f}s +{len(ch)}B hex={ch[:80].hex()}", flush=True)
    print(f"  [{pvn}] TOTAL {total}B")
    s.close()

print(f"== raw status probe, wait {WAIT}s ==")
for pvn in (775, 767):
    do(pvn, send_status_req=True)
print("== raw login probe ==")
do(775, send_status_req=False, send_login=True)
