import socket, os, sys
sys.path.insert(0,'.')
from mcddos import protocol as mc
P=int(os.environ.get('P','775'))
s = socket.create_connection(('play.cubecraft.net', 25565), timeout=20)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
hs = mc.handshake_payload(P, 'play.cubecraft.net', 25565, 2)
s.sendall(mc.varint(len(hs)+1) + mc.varint(0) + hs)
ls = mc.varint(0) + mc.str_field('mcddosprobe') + b'\x00'*16
s.sendall(mc.varint(len(ls)) + ls)
s.settimeout(12)
buf=b''
t0=__import__('time').time()
while __import__('time').time()-t0 < 14:
    try:
        ch = s.recv(65536)
    except Exception as e:
        print('recv stop', type(e).__name__, 'at t=', round(__import__('time').time()-t0,1))
        break
    if not ch:
        print('closed'); break
    buf += ch
    print('chunk', len(ch), 'cum', len(buf))
    if len(buf) < 3: continue
    # parse frames from buf
    pos=0
    while pos < len(buf):
        b=buf[pos]
        ln=b&0x7F; sh=7; p1=pos+1
        while b&0x80:
            if p1>=len(buf): break
            b=buf[p1]; ln|=(b&0x7F)<<sh; sh+=7; p1+=1
        if p1>=len(buf): break
        if p1+ln > len(buf): break
        body=buf[p1:p1+ln]
        pid=mc.Reader(body,P).read_varint()
        print(f'  FRAME len={ln} pid={pid}')
        if pid==1:
            r2=mc.Reader(body,P)
            uuid=r2.read_bytes(16); kl=r2.read_varint(); key=body[r2.pos:r2.pos+kl]
            print(f'    encryption_begin uuid={uuid.hex()} keylen={kl} der={key[:12].hex()}')
        elif pid==0:
            r2=mc.Reader(body,P)
            try:
                import json
                j=json.loads(r2.read_string())
                def flat(o):
                    if isinstance(o,dict):
                        return o.get('text','')+(''.join(flat(x) for x in o.get('extra',[])) if isinstance(o.get('extra'),list) else '')
                    if isinstance(o,list): return ''.join(flat(x) for x in o)
                    return str(o)
                print('    DISCONNECT:', flat(j)[:150])
            except Exception as e: print('    parse err', e)
        elif pid==2:
            r2=mc.Reader(body,P); uuid=r2.read_bytes(16); nm=r2.read_string()
            print('    LOGIN SUCCESS', uuid.hex(), nm)
        elif pid==3:
            r2=mc.Reader(body,P); print('    COMPRESS threshold', r2.read_varint())
        elif pid==4:
            r2=mc.Reader(body,P); mid=r2.read_varint(); ch2=r2.read_string()
            print('    PLUGIN_REQ', mid, ch2, body[r2.pos:r2.pos+60].hex())
        pos = p1+ln
