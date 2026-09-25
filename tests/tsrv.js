const mc = require('minecraft-protocol');
const port = parseInt(process.env.PORT || '25565');
const version = process.env.VVER || '1.21.1';
const server = mc.createServer({
  host: '127.0.0.1', port, version,
  maxPlayers: 50, motd: 'MCDDOS test ' + version, 'online-mode': false,
});
let ka = 0;
server.on('online', (client) => {
  console.log('CLIENT', client.username, version);
  const iv = setInterval(() => { try { client.send('keepalive', { id: ka++ }); } catch (e) {} }, 1500);
  client.on('end', () => clearInterval(iv));
  client.on('chat', (msg) => console.log('CHAT', client.username, JSON.stringify(msg)));
});
console.log('listening', port, version);
