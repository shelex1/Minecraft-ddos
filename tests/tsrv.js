const mc = require('minecraft-protocol');
const port = parseInt(process.env.PORT || '25565');
const version = process.env.VVER || '1.21.1';
const server = mc.createServer({
  host: '127.0.0.1', port, version,
  maxPlayers: 50, motd: 'MCDDOS test ' + version, 'online-mode': false,
});
let ka = 0;
// minecraft-protocol v1.58: события 'login' (после login_success) и 'playerJoin' (play-state).
// offline-режим: ванильный node-сервер кикает за пустую mojang-подпись
// в chat_session_update (cracked-игрок не может подписаться ключом Mojang).
// Настоящие offline-серверы (Bungee/анти-бот) принимают любой RSA-ключ —
// глотаем именно этот кик.
server.on('login', (client) => {
  console.log('CLIENT', client.username, version);
  client.on('playerJoin', () => console.log('PLAYERJOIN (play state) for', client.username));
  const origEnd = client.end.bind(client);
  client.end = (reason, data) => {
    const t = String((data && (data.text || data)) || reason || '');
    if (t.includes('invalid_public_key_signature')) {
      console.log('SWALLOWED kick (offline profile key) for', client.username);
      return;
    }
    console.log('KICK', client.username, JSON.stringify(t).slice(0, 200));
    return origEnd(reason, data);
  };
  const iv = setInterval(() => { try { client.send('keepalive', { id: ka++ }); } catch (e) {} }, 1500);
  client.on('end', () => clearInterval(iv));
  client.on('chat', (msg) => console.log('CHAT', client.username, JSON.stringify(msg)));
});
console.log('listening', port, version);
