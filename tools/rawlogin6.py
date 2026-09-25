import socket, os, sys, select
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST=sys.argv[1] if len(sys.argv)>1 else 'org.earthmc.net'
P=int(os.environ.get('P','767'))
s = socket.create_connection((HOST, 25565), timeout=15)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, HOST, 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(10)
NAMES={0:'DISCONNECT',1:'encryption_begin',2:'login_success',3:'COMPRESS',4:'PLUGIN_REQ'}
buf=b''
import time
t0=time.time()
while time.time()-t0 < 11:
    r,_,_ = select.select([s],[],[],3)
    if not r:
        continue
    ch = s.recv(65536)
    if not ch:
        print('closed after', len(buf), 'bytes'); break
    buf += ch
while True:
    if len(buf) < 2: break
    b=buf[0]
    ln=b&0x7F; sh=7; p1=1
    while b&0x80:
        if p1>=len(buf): break
        b=buf[p1]; ln|=(b&0x7F)<<sh; sh+=7; p1+=1
    if p1>=len(buf) or p1+ln>len(buf): break
    body=buf[p1:p1+ln]
    pid=mc.Reader(body,P).read_varint()
    print(f'FRAME len={ln} pid={pid} ({NAMES.get(pid,"?")})')
    if pid==0:
        r2=mc.Reader(body,P)
        try:
            import json
            j=json.loads(r2.read_string())
            def flat(o):
                if isinstance(o,dict):
                    t=o.get('text','')
                    ex=o.get('extra')
                    if isinstance(ex,list): t+=''.join(flat(x) for x in ex)
                    return t
                if isinstance(o,list): return ''.join(flat(x) for x in o)
                return str(o)
            print('   REASON:', flat(j)[:250])
        except Exception as e: print('   parse err', e, body[:60].hex())
    elif pid==1:
        r2=mc.Reader(body,P); uuid=r2.read_bytes(16); kl=r2.read_varint()
        print('   encryption_begin keylen', kl)
    elif pid==2:
        r2=mc.Reader(body,P); uuid=r2.read_bytes(16); nm=r2.read_string()
        print('   SUCCESS', uuid.hex(), nm)
    elif pid==3:
        r2=mc.Reader(body,P); print('   threshold', r2.read_varint())
    elif pid==4:
        r2=mc.Reader(body,P); mid=r2.read_varint(); ch2=r2.read_string()
        print('   plugin channel:', ch2, 'rest:', body[r2.pos:r2.pos+40].hex())
    buf=buf[p1+ln:]
