import socket, os, sys, select
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST=sys.argv[1]
P=int(sys.argv[2]) if len(sys.argv)>2 else 767
s = socket.create_connection((HOST, 25565), timeout=15)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, HOST, 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(8)
buf=b''
t0=__import__('time').time()
while __import__('time').time()-t0 < 9:
    r,_,_=select.select([s],[],[],2)
    if r:
        ch=s.recv(65536)
        if not ch: break
        buf+=ch
print('total bytes:', len(buf))
print('hex:', buf.hex())
