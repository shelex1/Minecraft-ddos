import socket, struct, time
HOST='CoreLand.go-srv.top'; PORT=25565
def varint(v):
    out=b''
    while True:
        b=v&0x7f; v>>=7
        if v: out+=bytes([b|0x80])
        else: out+=bytes([b]); break
    return out
# query handshake
pkt = b'\x01' + varint(0x1234)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(pkt,(HOST,PORT))
try:
    d,_=s.recvfrom(1024)
    print('hs resp:', d[:16].hex())
    # split packet
    sp = d[:5] + b'\x02' + varint(0x1234) + struct.pack('>H', PORT) + b'\x01\x00'
    s.sendto(sp,(HOST,PORT))
    d2,_=s.recvfrom(4096)
    print('query resp len:', len(d2))
    txt=d2.decode('utf-8','replace')
    print(txt)
except Exception as e:
    print('query err', type(e).__name__, e)
