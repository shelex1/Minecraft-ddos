const net=require('net');
const origWrite=net.Socket.prototype.write;
net.Socket.prototype.write=function(chunk,enc,cb){
  console.log('NODE SEND', Buffer.isBuffer(chunk)?chunk.toString('hex'):Buffer.from(chunk).toString('hex'));
  return origWrite.call(this,chunk,enc,cb);
};
const origOn=net.Socket.prototype.on;
net.Socket.prototype.on=function(ev,fn){
  if(ev==='data'){
    const wrap=(d)=>{console.log('NODE RECV',d.toString('hex'));fn(d);};
    return origOn.call(this,'data',wrap);
  }
  return origOn.apply(this,[ev,fn]);
};
const mc=require('minecraft-protocol');
mc.ping({host:'CoreLand.go-srv.top',port:25565,version:769,timeout:12000},(e,s)=>{
  console.log(e?'ERR '+e.message:'OK');
  process.exit(0);
});
