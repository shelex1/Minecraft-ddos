import socket, select, time, sys, struct
sys.path.insert(0, '.')
from mcddos import protocol as mc

HOST = "CoreLand.go-srv.top"

def wait_bytes(s, t):
    t0 = time.time(); total = 0
    while time.time() - t0 < t:
        r, _, _ = select.select([s], [], [], 1.5)
        if r:
            try:
                ch = s.recv(65536)
            except Exception as e:
                print(f"    recv exc {type(e).__name__}")
                break
            if not ch:
                print(f"    CLOSED at {time.time()-t0:.1f}s after {total}B")
                break
            total += len(ch)
            print(f"    t={time.time()-t0:.1f}s +{len(ch)}B {ch[:60].hex()}")
    return total

def tcp_probe(pvn, mode, wait):
    s = socket.create_connection((HOST, 25565), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    hs = mc.handshake_payload(pvn, HOST, 25565, 2 if mode in ("login","both") else 1)
    s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
    time.sleep(0.15)
    if mode in ("status","both"):
        s.sendall(b"\x01\x00")
    if mode == "login":
        ls = mc.varint(0) + mc.str_field("probe") + b"\x00"*16
        s.sendall(mc.varint(len(ls)) + ls)
    print(f"  [{mode} pvn={pvn}] waiting {wait}s ...")
    t = wait_bytes(s, wait)
    print(f"  [{mode} pvn={pvn}] -> {t}B")
    s.close()
    time.sleep(1)

def udp_query(wait=6):
    print("  [UDP query] ...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(wait)
    pkt = b"\x01" + mc.varint(0x1234)
    s.sendto(pkt, (HOST, 25565))
    try:
        d,_ = s.recvfrom(1024)
        print(f"    hs resp {len(d)}B {d[:20].hex()}")
        sp = d[:5] + b"\x02" + mc.varint(0x1234) + struct.pack(">H",25565) + b"\x01\x00"
        s.sendto(sp,(HOST,25565))
        d2,_ = s.recvfrom(4096)
        print(f"    query resp {len(d2)}B text={d2.decode('utf-8','replace')[:200]}")
    except Exception as e:
        print(f"    udp err {type(e).__name__} {e}")
    s.close()

def bedrock(wait=6):
    print(f"  [bedrock 19132] waiting {wait}s ...")
    try:
        s = socket.create_connection((HOST, 19132), timeout=8)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
        s.sendall(b"\x01\x12\x00")
        t = wait_bytes(s, wait)
        print(f"    -> {t}B")
        s.close()
    except Exception as e:
        print(f"    err {type(e).__name__} {e}")

print("=== long status 775 ===")
tcp_probe(775, "status", 50)
print("=== handshake only 775 ===")
tcp_probe(775, "none", 20)
print("=== UDP query ===")
udp_query()
print("=== bedrock ===")
bedrock()
print("=== old protocol 47 (1.8) status ===")
tcp_probe(47, "status", 20)
print("DONE")
