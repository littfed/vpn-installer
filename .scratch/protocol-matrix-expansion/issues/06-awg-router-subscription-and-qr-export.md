# 06: Доставка подписок для роутеров: эндпоинт ?format=awg и экспорт QR в CLI

**What to build:**
Реализация доставки конфигураций AmneziaWG для роутеров (Keenetic, OpenWrt) и мобильного клиента Amnezia VPN. Сервер подписок `sub-server.py` начинает обслуживать эндпоинт `https://<host>/sub/<token>?format=awg`, отдавая готовый `.conf` файл с персональным приватным ключом, назначенным IP-адресом туннеля, публичным ключом сервера, эндпоинтом ноды и всеми параметрами обфускации (`H1–H4`, `Jc`, `Jmin/Jmax`, `S1/S2`). Команда CLI `vpn user show <name>` дополняется выводом полной текстовой конфигурации AmneziaWG и генерацией ASCII QR-кода прямо в терминале для быстрого сканирования камерой смартфона.

**Blocked by:** 04: Расширение модели Identity: генерация Curve25519-ключей и IP-пула для AWG, 05: Сервис amneziawg-go в Docker Compose и генератор параметров обфускации (v2.0/v3.1)

**Status:** resolved

- [x] В `scripts/sub-server.py` добавлен обработчик `?format=awg`, возвращающий `Content-Type: text/plain` (или `application/octet-stream` с `Content-Disposition: attachment; filename="<username>-awg.conf"`).
- [x] Конфиг `.conf` содержит секцию `[Interface]` с клиентским `PrivateKey`, `Address = 10.8.0.X/32`, `DNS = 1.1.1.1, 77.88.8.8` и параметрами `Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4`.
- [x] Конфиг содержит секцию `[Peer]` с `PublicKey` сервера ноды, `Endpoint = <node-ip>:48291` и `AllowedIPs = 0.0.0.0/0, ::/0`.
- [x] При наличии нескольких зарубежных нод эндпоинт `?format=awg` позволяет выбирать ноду через параметр `&node=<name>` или отдает ZIP/архив либо мульти-конфиг.
- [x] Команда `vpn user show <name>` отображает блок AmneziaWG и генерирует QR-код через встроенный терминальный генератор (qrencode).
