import socket, threading, select, sys

def handle(c, addr):
    print("CONN from", addr, flush=True)
    try:
        data=b""
        while b"\r\n\r\n" not in data:
            chunk=c.recv(4096)
            data += chunk
            print("recv", len(chunk), chunk[:80].hex(), flush=True)
            if not chunk:
                print("client closed early", flush=True); c.close(); return
        hostport=data.split(b" ")[1].decode()
        host,_,port=hostport.partition(":")
        port=int(port)
        print(f"CONNECT to {host}:{port}", flush=True)
        t=socket.create_connection((host,port),timeout=5)
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        print("sent 200", flush=True)
        while True:
            r,_,_=select.select([c,t],[],[],15)
            if c in r:
                d=c.recv(65536)
                if not d: break
                t.sendall(d)
            if t in r:
                d=t.recv(65536)
                if not d: break
                c.sendall(d)
    except Exception as e:
        print("handle err", type(e).__name__, e, flush=True)
    finally:
        try: c.close()
        except: pass

srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",3129)); srv.listen(50)
print("proxy up 3129", flush=True)
while True:
    c,a=srv.accept()
    threading.Thread(target=handle,args=(c,a),daemon=True).start()
