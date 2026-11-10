# 01: Движок синтетического зондирования на базе sing-box (canary-probe.py)

**What to build:**
Автономный скрипт `scripts/canary-probe.py` для тестирования доступности зарубежных нод изнутри РФ через нативный клиент `sing-box`. Для каждой ноды и протокола из `nodes.json` скрипт запускает временный изолированный фоновый процесс `sing-box` с локальным inbound (например, `127.0.0.1:<random_port>`) и выполняет сквозные замеры через `curl`.

**Blocked by:** none

**Status:** resolved

## Acceptance criteria

- [x] Скрипт принимает аргументы `--nodes-file <path>`, `--health-file <path>`, `--timeout <sec>`, `--dry-run`.
- [x] Для протокола VLESS Reality генерируется минимальный временный клиентский конфиг `sing-box` с outbound VLESS Reality и inbound `mixed` на случайном свободном loopback-порту.
- [x] Для протокола Hysteria 2 генерируется клиентский конфиг `sing-box` с outbound Hysteria 2 с поддержкой `pinSHA256` / `pinnedPeerCertSha256` (или `insecure: true` в зависимости от наличия отпечатка).
- [x] Для MTProto Proxy выполняется тест TCP-соединения на целевой порт (8443) и валидация отклика.
- [x] Через поднятый `mixed/socks5` порт выполняются 3 сквозных HTTP-запроса:
  1. `https://cp.cloudflare.com/generate_204` — фиксация времени отклика (RTT в мс).
  2. `https://www.youtube.com` или `https://www.instagram.com` — подтверждение обхода блокировок ТСПУ (код 200/301/302).
  3. `https://api.openai.com` — подтверждение чистоты IP и работоспособности WARP egress ноды.
- [x] Временный процесс `sing-box` корректно завершается (SIGTERM, затем SIGKILL при необходимости), а временные файлы конфигов удаляются.
- [x] Время тестирования одного протокола ограничено таймаутом (по умолчанию 5 секунд на запрос).
- [x] Скрипт возвращает структурированный JSON с результатами: `node`, `protocol`, `latency_ms`, `tspu_bypass_ok`, `warp_ok`, `success`.
