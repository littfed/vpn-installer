# 05: Фоновый демон мониторинга на базе systemd (vpn-canary.timer)

**What to build:**
Служба и таймер systemd (`vpn-canary.service` и `vpn-canary.timer`) для автоматического периодического запуска скрипта зонда `canary-probe.py` на сервере в РФ с интервалом раз в 7 минут и рандомизированным джиттером.

**Blocked by:** 01: Движок синтетического зондирования на базе sing-box, 02: Реестр здоровья нод и логика Circuit Breaker

**Status:** resolved

## Acceptance criteria

- [x] Создан файл юнита `/etc/systemd/system/vpn-canary.service`:
  - `Type=oneshot`
  - `ExecStart=/usr/bin/python3 /opt/vpn-installer/scripts/canary-probe.py --nodes-file /opt/vpn-installer/nodes.json --health-file /opt/vpn-installer/node-health.json`
  - `StandardOutput=journal`
  - `StandardError=journal`
- [x] Создан файл таймера `/etc/systemd/system/vpn-canary.timer`:
  - `OnBootSec=1min`
  - `OnUnitActiveSec=7min`
  - `RandomizedDelaySec=60s` (рандомизированный разброс запуска для исключения периодического паттерна трафика, привлекающего DPI)
  - `Persistent=true`
- [x] Скрипт установки/настройки регистрирует, включает и запускает таймер: `systemctl enable --now vpn-canary.timer`.
- [x] Статус работы таймера проверяется через `systemctl list-timers --all | grep vpn-canary`.
- [x] Ротация логов выполняется стандартными средствами systemd-journald без риска переполнения диска.
