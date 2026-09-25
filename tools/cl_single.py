import socket, select, time, sys, json
sys.path.insert(0, '.')
from mcddos import protocol as mc

HOST = "CoreLand.go-srv.top"

def probe(pvn, mode="status", single=False, nodelay=True, wait=15):
    s = socket.create_connection((HOST, 25565), timeout=15)
    if nodelay:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    nxt = 2 if mode in ("login","both") else 1
    hs = mc.handshake_payload(pvn, HOST, 25565, nxt)
    head = mc.varint(len(hs) + 1) + mc.varint(0) + hs
    if single and mode != "login":
        s.sendall(head + b"\x01\x00")
    else:
        s.sendall(head)
        time.sleep(0.05)
        if mode in ("status","both"):
            s.sendall(b"\x01\x00")
        if mode == "login":
            ls = mc.varint(0) + mc.str_field("p") + b"\x00"*16
            s.sendall(mc.varint(len(ls)) + ls)
    t0 = time.time(); buf = b""
    while time.time() - t0 < wait:
        r,_,_ = select.select([s],[],[],1.5)
        if r:
            try: ch = s.recv(65536)
            except Exception as e:
                s.close(); return f"exc {type(e).__name__}"
            if not ch:
                s.close(); return "closed"
            buf += ch
            if len(buf) > 2: break
    s.close()
    if len(buf) > 2:
        b = buf[0]; ln = b & 0x7f; sh = 7; p1 = 1
        while b & 0x80:
            b = buf[p1]; ln |= (b & 0x7f) << sh; sh += 7; p1 += 1
        try:
            d = json.loads(buf[p1:p1+ln].decode("utf-8","replace"))
            return "OK " + str(d.get("version",{}).get("name"))[:40]
        except Exception as e:
            return f"got {len(buf)}B {buf[:40].hex()}"
    return "silent"

for pvn in (775, 767):
    print(f"pvn={pvn} sep+nd     -> {probe(pvn)}")
    print(f"pvn={pvn} single     -> {probe(pvn, single=True)}")
    print(f"pvn={pvn} sep no-nodelay -> {probe(pvn, nodelay=False)}")
    time.sleep(1)
