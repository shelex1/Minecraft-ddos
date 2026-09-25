import socket, sys, select, time
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='top.zetrex.net'; P=767

def rd(f): return mc.Reader(f,P)

def recv_avail(s,t=8):
    buf=b''; t0=time.time()
    while time.time()-t0 < t:
        r,_,_=select.select([s],[],[],1.0)
        if r:
            try: ch=s.recv(65536)
            except Exception as e: print('  recv exc',e); return buf
            if not ch: break
            buf+=ch
    return buf

def frames(buf):
    out=[]; pos=0
    while pos < len(buf):
        b=buf[pos]; ln=b&0x7F; sh=7; p1=pos+1
        while b&0x80:
            if p1>=len(buf): break
            b=buf[p1]; ln|=(b&0x7F)<<sh; sh+=7; p1+=1
        if p1>=len(buf) or p1+ln>len(buf): break
        out.append(buf[p1:p1+ln]); pos=p1+ln
    return out

def settings_payload():
    p=mc.varint(0)
    p+=mc.str_field('en_US'); p+=bytes([12]); p+=mc.varint(15); p+=b'\x01'
    p+=bytes([255]); p+=mc.varint(1); p+=b'\x00'; p+=b'\x01'
    return p

ok=False
for attempt in range(4):
    try:
        s = socket.create_connection((HOST,25565), timeout=15)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
        hs = mc.handshake_payload(P, HOST, 25565, 2)
        s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
        ls = mc.varint(0)+mc.str_field('mcddosprobe'+str(attempt))+b'\x00'*16
        s.sendall(mc.varint(len(ls))+ls)
        s.settimeout(8)
        print(f'== attempt {attempt}: reading login response ==')
        got_success=False
        t0=time.time()
        while time.time()-t0 < 20:
            buf=recv_avail(s,6)
            if not buf: 
                if time.time()-t0>20: break
                continue
            print(f'  got {len(buf)}B hex:', buf.hex()[:100])
            for f in frames(buf):
                pid=rd(f).read_varint()
                print(f'  S2C pid={pid} len={len(f)}')
                if pid==2:
                    r=rd(f)
                    try:
                        uuid=r.read_bytes(16); nm=r.read_string()
                        print(f'    LOGIN SUCCESS uuid={uuid.hex()} name={nm} rest={f[r.pos:r.pos+4].hex()}')
                    except Exception as e:
                        print('    parse err', e, 'hex', f.hex())
                    got_success=True
                    s.sendall(mc.varint(3))
                    print('    -> sent login_ack')
                elif pid==5:  # cookie_request (login state)
                    r=rd(f); mid=r.read_varint(); ch=r.read_string()
                    print(f'    COOKIE_REQ mid={mid} ch={ch}')
                    # cookie_response: mid varint, channel string, hasValue bool, [value]
                    cr=mc.varint(mid)+mc.str_field(ch)+b'\x00'
                    s.sendall(mc.varint(4)+mc.varint(len(cr))+cr)
                    print('    -> sent cookie_response (empty value)')
                elif pid==3:
                    print('    COMPRESS', rd(f).read_varint())
                elif pid==4:
                    r=rd(f); mid=r.read_varint(); ch=r.read_string()
                    print(f'    PLUGIN_REQ {ch}')
                    s.sendall(mc.varint(2)+mc.varint(mid)+mc.varint(1))
                elif pid==0:
                    r=rd(f)
                    try:
                        import json
                        j=json.loads(r.read_string())
                        def flat(o):
                            if isinstance(o,dict):
                                t=o.get('text',''); ex=o.get('extra')
                                return t+(''.join(flat(x) for x in ex) if isinstance(ex,list) else '')
                            if isinstance(o,list): return ''.join(flat(x) for x in o)
                            return str(o)
                        print('    DISCONNECT:', flat(j)[:200])
                    except Exception: print('    DISCONNECT hex', f[:40].hex())
            if got_success: break
        # config phase
        print('  -> config: sending settings')
        sp=settings_payload()
        s.sendall(mc.varint(len(sp))+sp)
        time.sleep(0.3)
        buf=recv_avail(s,5)
        print(f'  after settings: {len(buf)}B hex:', buf.hex()[:150])
        for f in frames(buf):
            pid=rd(f).read_varint()
            print(f'    S2C pid={pid}')
            if pid==0:
                try: print('    DISCONNECT:', rd(f).read_string()[:150])
                except Exception: print('    DISCONNECT hex', f[:40].hex())
        print('  -> sending finish_configuration')
        s.sendall(mc.varint(3))
        time.sleep(0.5)
        buf=recv_avail(s,8)
        print(f'  after finish: {len(buf)}B hex:', buf.hex()[:250])
        for f in frames(buf):
            pid=rd(f).read_varint()
            print(f'    S2C pid={pid} (config: 3=finish 4=keepalive 0=disc | play: 36=keepalive 43=join)')
        ok=True
        break
    except Exception as e:
        print(f'attempt {attempt} ERR {type(e).__name__}: {e}')
    time.sleep(2)
print('DONE', 'ok' if ok else 'fail')
