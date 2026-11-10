# 01: Базовый инсталлер и Docker Compose с ядром Sing-box

**What to build:**
Скрипт начальной установки и базовая CLI-утилита, которая подготавливает структуру каталогов `/opt/vpn-installer/`, проверяет системные зависимости (Docker, Docker Compose, curl), генерирует начальные криптографические ключи сервера Reality (PrivateKey, PublicKey, ShortId) в `manifest.json` и запускает контейнер `sing-box` в режиме `network_mode: host`. Сервер начинает слушать порты `443/TCP` (VLESS Reality) и `443/UDP` (Hysteria 2).

**Blocked by:** None (can start immediately)

**Status:** resolved

## Acceptance criteria

- [x] Скрипт установки проверяет поддерживаемые ОС (Ubuntu 22.04/24.04, Debian 11/12) и права root.
- [x] Если Docker / Docker Compose не установлены, установщик автоматически и корректно устанавливает их.
- [x] Создаётся директория `/opt/vpn-installer/` с правами `chmod 700` и симлинк исполняемого файла CLI `/usr/local/bin/vpn`.
- [x] Генерируется файл `manifest.json`, содержащий сгенерированные ключи сервера Reality, UUID ноды и порт.
- [x] Генерируется базовый валидный `config.json` для sing-box.
- [x] Контейнер `sing-box` успешно поднимается через Docker Compose в `network_mode: host` с правами `NET_ADMIN`.
- [x] Проверка открытых портов подтверждает прослушивание `443/TCP` и `443/UDP`.
- [x] Команда `vpn status` выводит текущее состояние сервисов и сетевых портов.
