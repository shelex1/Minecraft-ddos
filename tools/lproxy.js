const net=require('net');
const port=+process.argv[2];
const target=process.argv[3];
const tport=+process.argv[4];
const srv=net.createServer(sock=>{
  console.log('CLIENT CONNECT');
  const up=net.connect(tport,target);
  // pipe immediately (buffers until upstream connects)
  sock.pipe(up); up.pipe(sock);
  up.on('connect',()=>console.log('UPSTREAM CONNECTED'));
  sock.on('data',d=>{console.log('C2S',d.toString('hex'));});
  up.on('data',d=>{console.log('S2C',d.toString('hex'));});
  up.on('error',e=>console.log('up err',e.message));
  sock.on('error',e=>console.log('sock err',e.message));
  sock.on('close',()=>console.log('closed'));
});
srv.listen(port,()=>console.log('proxy on',port));
setTimeout(()=>{console.log('proxy timeout');process.exit(0);},12000);
