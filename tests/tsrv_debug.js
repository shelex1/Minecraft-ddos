// tsrv_debug.js — сервер с полным логом событий и s2c-пакетов
const mc = require('minecraft-protocol');
const port = parseInt(process.env.PORT || '25577');
const version = process.env.VVER || '1.21.1';
const server = mc.createServer({
  host: '127.0.0.1', port, version,
  maxPlayers: 50, motd: 'MCDDOS test ' + version, 'online-mode': false,
});
for (const ev of ['connection', 'login', 'playerJoin', 'online', 'end', 'error']) {
  server.on(ev, (...a) => {
    const who = a[0] && a[0].username ? a[0].username : '';
    console.log('EV', ev, who, a.length > 1 ? String(a[1]).slice(0, 120) : '');
  });
}
server.on('connection', (client) => {
  const origWrite = client.write.bind(client);
  client.write = (name, params) => {
    console.log('S2C', name, JSON.stringify(params).slice(0, 200));
    return origWrite(name, params);
  };
  const origEnd = client.end.bind(client);
  client.end = (reason, data) => {
    console.log('END-CALL', String(reason).slice(0, 100), JSON.stringify(data || '').slice(0, 200));
    return origEnd(reason, data);
  };
  client.on('error', (e) => console.log('CLIENT-ERR', String(e.message || e).slice(0, 200)));
  client.on('chat_session_update', () => console.log('C2S chat_session_update'));
  client.on('chat', (m) => console.log('CHAT', JSON.stringify(m).slice(0, 150)));
});
console.log('listening', port, version);
