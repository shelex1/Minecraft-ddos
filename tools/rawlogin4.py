import socket, os, sys, select
sys.path.insert(0,'.')
from mcddos import protocol as mc
P=int(os.environ.get('P','775'))
s = socket.create_connection(('play.cubecraft.net', 25565), timeout=30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, 'play.cubecraft.net', 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(15)
def rf(s, tag=''):
    b=s.recv(1)
    if not b: return None
    ln=b[0]&0x7F
    sh=7
    while b[0]&0x80:
        n=s.recv(1)
        if not n: return None
        ln|=(n[0]&0x7F)<<sh
        sh+=7
        b=n
    body=b''
    while len(body)<ln:
        ch=s.recv(ln-len(body))
        if not ch: break
        body+=ch
    return ln,body
NAMES={0:'disconnect',1:'encryption_begin',2:'login_success',3:'compress',4:'login_plugin_request'}
import traceback
try:
    for i in range(4):
        r=rf(s)
except Exception as e:
    print('stop:', type(e).__name__)
    sys.exit(0)
for i in range(0):
    r=None
    if r is None: print(f'[{i}] CLOSED'); break
    ln,body=r
    pos=0
    pid=mc.Reader(body,P).read_varint()
    print(f'[{i}] pid={pid} ({NAMES.get(pid,"?")}) len={ln}')
    if pid==0:
        r2=mc.Reader(body,P)
        try:
            import json
            j=json.loads(r2.read_string())
            def flat(o):
                if isinstance(o,dict):
                    if 'text' in o: return o['text']
                    return ''.join(flat(x) for x in o.get('extra',[]))
                if isinstance(o,list): return ''.join(flat(x) for x in o)
                return str(o)
            print('   KICK:', flat(j)[:200])
        except Exception as e: print('   parse',e)
        break
    if pid==1:
        r2=mc.Reader(body,P)
        uuid=r2.read_bytes(16)
        keylen=r2.read_varint()
        key=body[r2.pos:r2.pos+keylen]
        print(f'   server pubkey {keylen}B, DER starts {key[:16].hex()} (EC P-256 PKCS8)')
    if pid==2:
        r2=mc.Reader(body,P)
        uuid=r2.read_bytes(16)
        nm=r2.read_string()
        print('   LOGIN SUCCESS uuid=',uuid.hex(),'name=',nm)
