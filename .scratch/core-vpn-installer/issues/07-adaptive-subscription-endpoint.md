# 07: Адаптивный эндпоинт выдачи подписок (/sub/<token>)

**What to build:**
Опциональная подсистема выдачи подписок (`--enable-sub-web`), работающая за Caddy по адресу `https://<domain>/sub/<secret_token>`. Эндпоинт анализирует заголовок `User-Agent` клиентского запроса и динамически возвращает подходящий формат: Clash.Meta / Mihomo YAML (с группами auto-failover `url-test`), Sing-box JSON (с преднастроенным L3 TUN и Split-Tunneling для РФ) или Base64 URI list.

**Blocked by:** 02: Реестр пользователей и CLI, 05: Сайт-заглушка (Caddy)

**Status:** resolved

## Acceptance criteria

- [x] Команда `vpn system enable-sub` активирует эндпоинт подписок, защищённый длинным случайным 32-байтным токеном в `users.json`.
- [x] Запрос с заголовком `User-Agent: Clash.Meta` или `clash-verge` возвращает валидный YAML профиль с правилами `url-test`, `fallback` и селектором стран.
- [x] Запрос с заголовком `User-Agent: sing-box` возвращает готовый клиентский `config.json` с настроенным L3 TUN, раздельным DNS (Яндекс DoH для `.ru`, зарубежный DoH для остального) и правилами обхода РФ (`geosite-ru` и `geoip-ru` -> `direct`).
- [x] Обычный браузерный запрос или запрос от Streisand/v2rayNG возвращает Base64-закодированный список URI (`vless://`, `hy2://`).
- [x] Поддерживается принудительное переопределение формата через параметр URL: `?format=clash`, `?format=singbox`, `?format=base64`.
- [x] Неверный или отсутствующий токен возвращает HTTP 404 без раскрытия существования сервиса подписок.
