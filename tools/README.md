# tools/ — вспомогательные и диагностические скрипты

Экспериментальный код (сырой, без единого формата). Группы:

- **`detect.py`** (в корне) — авто-детект: версия + реальный IP + капча.
- **`playtest.py`** — заход на сервер **как реальный игрок**: авто-версия,
  реальный IP (prelogin), логин → play, keepalive, чат, отчёт что произошло
  (JOINED / CAPTCHA / REGISTRATION / whitelist / online mode / KICK).
- **Извлечение packets.json** — `extract_final.py`, `extract_ids.py`,
  `extract_by_dir.py`, `extract_versions.py`, `patch_ids.py`
  (извлекают ID пакетов из `minecraft-data` → `mcddos/data/packets.json`).
- **Прокси** — `check_proxies.py` (живость + гео egress-IP),
  `lproxy.js`, `nodecap.js` (node-снифферы/hex-дамп).
- **Сканеры серверов** — `fullscan*.py`, `bigscan.py`, `live_scan.py`,
  `offline_scan.py`, `more_servers.py` (поиск offline-серверов в подсетях).
- **Диагностика конкретных серверов** — `cl_*.py`, `coreland_*.py`
  (CoreLand), `zraw*.py`, `zetrex*.py` (Zetrex), `rawlogin*.py`, `rawdump*.py`
  (сырые пробы логина/дампы).

Запуск: `python3 tools/<имя>.py ...` (часть скриптов ждёт аргументов —
смотреть `--help` / начало файла).
