# 03: Зондирование TUIC v5 в Canary Probe и CLI

**What to build:**
Расширение скрипта синтетического мониторинга `scripts/canary-probe.py` для тестирования протокола TUIC v5 с сервера в РФ. Тестирование выполняется через эфемерный sing-box с 3-точечной валидацией: задержка RTT (Cloudflare 204), обход ТСПУ (YouTube) и чистота исходящего IP (WARP egress к OpenAI). Результаты сохраняются в `node-health.json` с логикой Circuit Breaker (2 сбоя подряд -> degraded, 2 успеха подряд -> healthy). Табличный вывод `vpn probe` и `vpn node test` дополняется строкой TUIC v5 для каждой ноды.

**Blocked by:** 01: Инбаунд TUIC v5 в ядре sing-box и настройка сети, 02: Поддержка TUIC v5 в сервере подписок и балансировке AUTO-FASTEST

**Status:** ready-for-agent

- [ ] В `scripts/canary-probe.py` генератор эфемерного конфига sing-box создает outbound `tuic` на порт 8443 ноды.
- [ ] Выполняются 3 замера через TUIC туннель: Cloudflare 204 ping, прямой HTTP/3 / HTTPS запрос к ресурсу для проверки обхода ТСПУ, запрос к API OpenAI для проверки сквозного WARP egress.
- [ ] Логика Circuit Breaker обновляет историю и статус протокола `tuic` в `node-health.json`.
- [ ] Команды `vpn probe` и `vpn node test` поддерживают флаг `--protocol tuic` и выводят отдельную строку таблицы: `| Node-1 | TUIC-v5 | <rtt> ms | OK | OK | HEALTHY | 0/5 |`.
