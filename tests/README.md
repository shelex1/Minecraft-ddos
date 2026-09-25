# tests/ — локальные тесты

Нужны `node` и пакет `minecraft-protocol` (`npm i minecraft-protocol`).

```bash
node tests/tsrv.js &          # тестовый offline MC-сервер (порт 25570)
python3 tests/cproxy3.py &    # локальный HTTP CONNECT-прокси (3129)

python3 tests/smoke_status.py    # status ping
python3 tests/smoke_login.py     # login -> play (1.16.5/1.19.2/1.20.4/1.21.1)
python3 tests/smoke_bots.py      # боты: join + chat
python3 tests/smoke_keepalive.py # боты держат соединение 18s, 0 киков
python3 tests/chat_test.py       # signed chat
python3 tests/proxytest.py       # status+login через HTTP-прокси
```

`tsrv.js` — минимальный тестовый сервер на `minecraft-protocol`
(offline mode), чтобы не гонять тесты на живых серверах.
