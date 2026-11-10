# 01: Инбаунд TUIC v5 в ядре sing-box и настройка сети

**What to build:**
Добавление протокола TUIC v5 в базовый контейнер `sing-box` на зарубежных нодах. Протокол слушает порт `8443/UDP`, использует Google BBR для контроля перегрузок, переиспользует единый самоподписанный сертификат ноды с SHA-256 отпечатком и аутентифицирует пользователей по их каноническому UUID и паролю из `users.json`. Фаервол разрешает входящий UDP-трафик на порт 8443. Обновление пользователей (`vpn user add/sync`) атомарно перезагружает конфигурацию без прерывания существующих соединений.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Шаблон `templates/sing-box/config.json.template` и генератор конфигурации в `vpn-install.sh` содержат инбаунд `type: tuic`:
  - `listen: "::"`, `listen_port: 8443`
  - `congestion_control: "bbr"`
  - `tls`: включен, использует существующие сертификаты `server.crt` / `server.key` ноды
  - `users`: рендерятся из активных пользователей `users.json` с полями `uuid` и `password`
- [ ] Скрипты синхронизации пользователей `scripts/user-sync.sh` и `bin/vpn` сохраняют инбаунд TUIC v5 и корректно обновляют список активных пользователей с отправкой `SIGHUP` контейнеру `sing-box`.
- [ ] В скриптах фаервола (`templates/iptables-rules.sh`, UFW/nftables в `bin/vpn`) открыт порт `8443/UDP`.
- [ ] Команда `vpn status` отображает статус работы TUIC v5 на порту 8443/UDP.
