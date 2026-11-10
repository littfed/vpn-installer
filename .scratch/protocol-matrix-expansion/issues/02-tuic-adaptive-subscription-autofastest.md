# 02: Поддержка TUIC v5 в сервере подписок и балансировке AUTO-FASTEST

**What to build:**
Сервер подписок `sub-server.py` генерирует секции TUIC v5 для клиентов `sing-box` (формат JSON) и `Clash Meta` / `Mihomo` (формат YAML). Протокол автоматически включается в списки прокси и селекторы `proxy-auto` / `AUTO-FASTEST`, а также в Base64 URI экспорт (`tuic://`). Включение в пул динамической автобалансировки учитывает состояние здоровья ноды из `node-health.json`: если протокол помечен как `degraded`, он исключается из `AUTO-FASTEST`.

**Blocked by:** 01: Инбаунд TUIC v5 в ядре sing-box и настройка сети

**Status:** resolved

- [x] В `scripts/sub-server.py` функция `build_singbox_json` добавляет outbound `type: tuic` с хостом ноды, портом 8443, uuid/паролем пользователя, `congestion_control: "bbr"`, `tls.enabled: true` и `insecure: true` (или SHA-256 пиннингом).
- [x] В `scripts/sub-server.py` функция `build_clash_yaml` добавляет прокси типа `tuic` со всеми необходимыми атрибутами (`uuid`, `password`, `sni`, `skip-cert-verify: true`, `congestion-controller: bbr`).
- [x] Прокси TUIC v5 включается в группы селекторов `proxy-auto` и `proxy` при условии, что его статус в `node-health.json` равен `healthy`.
- [x] В `build_base64_uris` добавляется URI схемы `tuic://` с аннотацией `-DEGRADED` при сбое.
- [x] Эндпоинты `https://<host>/sub/<token>?format=singbox` и `?format=clash` корректно отдают конфигурации с TUIC v5.
