import socket, sys, select, time, zlib
sys.path.insert(0,'.')
from mcddos import protocol as mc
HOST='top.zetrex.net'; P=767
s = socket.create_connection((HOST,25565), timeout=15)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
hs = mc.handshake_payload(P, HOST, 25565, 2)
s.sendall(mc.varint(len(hs)+1)+mc.varint(0)+hs)
ls = mc.varint(0)+mc.str_field('mcddosprobe')+b'\x00'*16
s.sendall(mc.varint(len(ls))+ls)
s.settimeout(8)

def recv_avail(t=8):
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

def rd(f):
    return mc.Reader(f,P)

# step 1: read until login_success / compress / plugin_request
print('== reading login response ==')
buf=recv_avail(8)
print('got',len(buf),'bytes hex:',buf.hex()[:120])
for f in frames(buf):
    pid=rd(f).read_varint()
    print('  S2C pid=',pid,'len',len(f),'hex',f.hex()[:80])
    if pid==3:  # compress
        thr=rd(f).read_varint()
        print('  -> compression threshold',thr)
    if pid==4:  # plugin_request
        r=rd(f); mid=r.read_varint(); ch=r.read_string()
        print('  -> plugin_req channel',ch,'mid',mid,'rest',f[r.pos:r.pos+30].hex())
        s.sendall(mc.varint(2)+mc.varint(mid)+mc.varint(1))
    if pid==2:  # login success
        print('  -> LOGIN SUCCESS')
        s.sendall(mc.varint(3))  # login_ack
        print('  -> sent login_ack(3)')

# step 2: send settings (config 0x00)
def settings_payload():
    p=mc.varint(0)
    p+=mc.str_field('en_US')      # locale
    p+=bytes([12])                 # viewDistance i8
    p+=mc.varint(15)               # chatFlags
    p+=b'\x01'                     # chatColors bool
    p+=bytes([255])                # skinParts u8
    p+=mc.varint(1)                # mainHand
    p+=b'\x00'                     # enableTextFiltering
    p+=b'\x01'                     # enableServerListing
    return p
s.sendall(mc.varint(len(settings_payload()))+settings_payload())
print('== sent settings (len', len(settings_payload()),') ==')
time.sleep(0.5)
buf=recv_avail(6)
print('after settings got',len(buf),'hex:',buf.hex()[:200])
for f in frames(buf):
    pid=rd(f).read_varint()
    print('  S2C pid=',pid,'len',len(f),'hex',f.hex()[:100])

# step 3: send finish_configuration (config 0x03)
s.sendall(mc.varint(3))
print('== sent finish_configuration(3) ==')
time.sleep(1)
buf=recv_avail(8)
print('after finish got',len(buf),'hex:',buf.hex()[:300])
for f in frames(buf):
    pid=rd(f).read_varint()
    print('  S2C pid=',pid,'len',len(f))
