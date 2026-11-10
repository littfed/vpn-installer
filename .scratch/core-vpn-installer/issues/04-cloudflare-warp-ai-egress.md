# 04: Интеграция Cloudflare WARP Egress для обхода банов ИИ-сервисов

**What to build:**
Встроенная маршрутизация трафика к сервисам искусственного интеллекта через Cloudflare WARP (WireGuard outbound в sing-box). Сервер регистрируется в API WARP с получением чистых IP Anycast, а запросы клиентов к OpenAI, Claude, Gemini и Cursor прозрачно перенаправляются в этот туннель, исключая капчи Cloudflare Turnstile и баны датацентров.

**Blocked by:** 01: Базовый инсталлер и Docker Compose с ядром Sing-box

**Status:** resolved

## Acceptance criteria

- [x] Реализован автономный скрипт `scripts/generate-warp-keys.py` (или bash-эквивалент), регистрирующий учётную запись через Cloudflare API и возвращающий PrivateKey, IPv4/IPv6 адреса и 3-байтовый `reserved` client ID.
- [x] В `config.json` добавляется outbound типа `wireguard` с тегом `warp-out`.
- [x] Настроены правила маршрутизации (`route.rules`) с использованием `geosite-openai`, `geosite-anthropic`, `geosite-google`, `geosite-cursor`, направляющие трафик в `warp-out`.
- [x] Настроен динамический `remote rule-set` для обновления правил геолокации и доменов без перезапуска.
- [x] Обычный интернет-трафик продолжает выходить напрямую через `direct`, не перегружая WARP.
- [x] Тестовый запрос изнутри туннеля на `https://www.cloudflare.com/cdn-cgi/trace` возвращает статус `warp=on`.
