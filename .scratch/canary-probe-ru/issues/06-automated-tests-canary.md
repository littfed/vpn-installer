# 06: Автоматические тесты функционала Canary Probe

**What to build:**
Пакет автоматизированных тестов `tests/test_canary_probe.py` для непрерывной интеграции и валидации всех сценариев работы Canary Probe.

**Blocked by:** 01: Движок синтетического зондирования на базе sing-box, 02: Реестр здоровья нод и логика Circuit Breaker, 04: Интеграция подписок с реестром здоровья нод

**Status:** resolved

## Acceptance criteria

- [x] Тест генерации временных конфигов sing-box для VLESS Reality и Hysteria 2: проверяется корректность структуры JSON, отсутствие устаревших полей, поддержка отпечатка сертификата `pinSHA256`.
- [x] Модульный тест логики Circuit Breaker:
  - 1 сбой $\rightarrow$ статус остается `healthy`, `consecutive_failures=1`.
  - 2 сбоя подряд $\rightarrow$ статус переходит в `degraded`, `consecutive_failures=2`.
  - 1 успешный замер после деградации $\rightarrow$ статус остается `degraded`, `consecutive_successes=1`.
  - 2 успешных замера подряд $\rightarrow$ статус восстанавливается в `healthy`.
- [x] Тест фильтрации подписок в `sub-server.py`:
  - При наличии деградировавших протоколов в `node-health.json` они корректно исключаются из `AUTO-FASTEST` в Clash YAML и из `proxy-auto` в Sing-box JSON.
  - При отсутствии файла `node-health.json` подписка выдает все сконфигурированные ноды без ошибок (graceful fallback).
- [x] Тест CLI `vpn probe --json` и форматированного вывода таблицы на моковых данных зонда.
- [x] Все тесты выполняются без ошибок через `pytest tests/test_canary_probe.py`.
