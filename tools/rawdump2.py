import socket, os, sys, select, time
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='top.zetrex.net'
P=767
last=b''
for attempt in range(5):
    try:
        s = socket.create_connection((HOST, 25565), timeout=15)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        hs = mc.handshake_payload(P, HOST, 25565, 2)
        s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
        ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
        s.sendall(mc.varint(len(ls)) + ls)
        s.settimeout(6)
        buf=b''
        t0=time.time()
        while time.time()-t0 < 7:
            r,_,_=select.select([s],[],[],1.5)
            if r:
                try:
                    ch=s.recv(65536)
                except Exception as e:
                    buf+=b'[RST]'
                    break
                if not ch: break
                buf+=ch
        if buf:
            print(f'attempt {attempt}: {len(buf)} bytes')
            print('hex:', buf.hex())
            break
    except Exception as e:
        print(f'attempt {attempt} err {type(e).__name__}')
    time.sleep(1)
