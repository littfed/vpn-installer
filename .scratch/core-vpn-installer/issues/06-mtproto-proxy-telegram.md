# 06: Интеграция MTProto Proxy (mtg v2) для Telegram

**What to build:**
Развёртывание легковесного демона MTProto Proxy (`9seconds/mtg` v2) в Docker Compose на порту `8443/TCP`. Сервис использует Fake-TLS маскировку с валидным доменом. Команда `vpn user show <name>` генерирует рабочую ссылку `tg://proxy?server=...&port=8443&secret=...` и QR-код для мгновенного подключения Telegram в один клик без установки VPN-клиента.

**Blocked by:** 02: Реестр пользователей и CLI (добавление, просмотр, ссылки и QR-коды)

**Status:** ready-for-agent

## Acceptance criteria

- [ ] В `docker-compose.yml` добавлен сервис `mtg` (образ `nineseconds/mtg:2`) в `network_mode: host`.
- [ ] Сервис `mtg` слушает порт `8443/TCP`.
- [ ] Секрет MTProto генерируется в формате Fake-TLS: префикс `ee` + 16 байт случайного секрета + hex-представление домена маскировки.
- [ ] Команда `vpn user show <name>` выводит синтаксически корректную ссылку вида `tg://proxy?server=<IP>&port=8443&secret=<SECRET>#Name`.
- [ ] Контейнер `mtg` стабильно работает с потреблением памяти не более 20 МБ RAM.
- [ ] Порт `8443/TCP` защищен от активного зондирования (anti-replay cache и сброс неавторизованных пакетов).
