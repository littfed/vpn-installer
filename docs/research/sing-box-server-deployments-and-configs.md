# Исследование серверных конфигураций, методов автоматизации и архитектурных решений для Sing-box

> **Цель исследования:** Детальный анализ существующих open-source решений развертывания `sing-box`, разработка эталонной мультипротокольной серверной конфигурации (VLESS-Reality + Hysteria 2 + TUIC v5 + Shadowsocks-2022), спецификация клиентских URI-схем и форматов подписок, а также формирование архитектуры автоматизированного инсталлятора `vpn-installer`.

---

## Содержание

1. [Анализ существующих Open-Source скриптов и систем развертывания](#1-анализ-существующих-open-source-скриптов-и-систем-развертывания)
   - 1.1. Обзор популярных проектов (chika0801, fscarmen, Hiddify, Marzban, Mack-a, 233boy, 3x-ui)
   - 1.2. Сравнительный анализ архитектур: Bash/systemd против Docker Compose
   - 1.3. Плюсы, минусы и «подводные камни» существующих инструментов
2. [Эталонная серверная конфигурация (Production-Ready Sing-box JSON)](#2-эталонная-серверная-конфигурация-production-ready-sing-box-json)
   - 2.1. Мультипротокольный `config.json` (VLESS-Reality, Hysteria 2, TUIC v5, Shadowsocks-2022)
   - 2.2. Защита от утечек и петель: Inbounds, Outbounds, Route Rules и DNS
   - 2.3. Блокировка приватных подсетей, мусорного трафика и BitTorrent
   - 2.4. Системная оптимизация ядра Linux (BBR, Fast Open, UDP/TCP сокетные буферы)
3. [Утилиты и автоматизация генерации криптографических параметров](#3-утилиты-и-автоматизация-генерации-криптографических-параметров)
   - 3.1. Встроенные команды `sing-box generate` (Reality Keypair, UUID, PSK/Rand)
   - 3.2. Алгоритм и скрипт валидации маскировочных SNI-доменов (TLS 1.3, ALPN h2, RTT, доступность в РФ)
   - 3.3. Настройка динамического Port Hopping для Hysteria 2 через `iptables` и `nftables`
4. [Спецификации клиентских ссылок и форматы подписок](#4-спецификации-клиентских-ссылок-и-форматы-подписок)
   - 4.1. Спецификация `vless://` (Reality + XTLS-Vision)
   - 4.2. Спецификация `hysteria2://` / `hy2://` (Salamander Obfs, Port Hopping)
   - 4.3. Спецификация `tuic://` (QUIC, BBR, Congestion Control)
   - 4.4. Спецификация `ss://` (Shadowsocks-2022 AEAD / SIP022)
   - 4.5. Универсальный формат комплексной подписки (Base64 URI List, Sing-box JSON, Mihomo/Clash.Meta YAML)
   - 4.6. Генерация терминальных и графических QR-кодов (`qrencode`)
5. [Рекомендуемая архитектура для `vpn-installer`](#5-рекомендуемая-архитектура-для-vpn-installer)
   - 5.1. Выбор среды развертывания: Docker Compose + официальный образ `ghcr.io/sagernet/sing-box`
   - 5.2. Модель хранения состояния и учетных данных (`manifest.json`)
   - 5.3. Механизм дистрибуции конфигураций (CLI + легковесный HTTP-эндпоинт подписки)
   - 5.4. Жизненный цикл, мониторинг и процедура автообновления
6. [Библиография, спецификации и первичные репозитории](#6-библиография-спецификации-и-первичные-репозитории)

---

## 1. Анализ существующих Open-Source скриптов и систем развертывания

### 1.1. Обзор популярных проектов

В экосистеме обхода цензуры сформировалось несколько основных подходов к автоматизации развертывания прокси-серверов:

| Проект / Репозиторий | Архитектура | Поддерживаемые ядра | Ключевые протоколы | Плюсы | Минусы |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **chika0801/sing-box-examples** | Репозиторий шаблонов (manual) | sing-box | Reality, Hysteria 2, TUIC, Shadowsocks, WireGuard | Чистый эталонный JSON, без лишних зависимостей, высокая наглядность | Нет автоматизации установки, ключи и сертификаты настраиваются вручную |
| **fscarmen/sing-box** («sing-box 全家桶») | Монолитный Bash-скрипт + systemd | sing-box | Reality, Hysteria 2, TUIC, Shadowsocks, VMess, Argo Tunnel | Быстрый старт, встроенный автовыпуск сертификатов, генерация подписок | «Спагетти-код» на тысячи строк bash, сложно поддерживать и модифицировать, риск перезаписи системных файлов |
| **233boy/sing-box** | Модульный Bash-скрипт + systemd | sing-box | Reality, Hysteria 2, TUIC, Trojan, Shadowsocks | Аккуратный TUI-интерфейс, быстродействие, простое CLI-управление | Жестко зашит под конкретные deb/rpm дистрибутивы, непрозрачные конфигурационные файлы |
| **Mack-a/v2ray-agent** (8-in-1) | Комплексный Bash CLI + systemd | Xray-core, sing-box | VLESS Reality/Vision/xHTTP, Hysteria 2, TUIC, Trojan, SS | Огромный функционал, ротация Cloudflare WARP, кастомные fallback | Перегружен функциями, тяжел для аудита безопасности, смешивает разные ядра |
| **hiddify-config / Hiddify-Manager** | Монолитный Docker/Python + Web-панель | sing-box, Xray-core | 20+ протоколов, Reality, Hysteria 2, TUIC, SSH, Shadowsocks | Полноценный Web GUI, встроенная экосистема клиентских приложений Hiddify, автогенерация подписок | Высокое потребление ОЗУ (от 1 ГБ), сложная отладка при падении, зависимость от БД и множества микросервисов |
| **Gozargah/Marzban** | Docker Compose (Python FastAPI + React + Xray/sing-box) | Xray-core (нативно), sing-box (через marzban-node/форки) | VLESS, VMess, Trojan, Shadowsocks | Идеальный биллинг/мультипользовательский учет, REST API, Telegram-бот, Web UI | Требует отдельный домен и SSL, не нацелен на ультралегковесные VPS (1 vCPU, 512 MB RAM) |
| **kevin1sme/sing-box-reality** | Узкоспециализированный Bash-скрипт | sing-box | VLESS-Reality | Минималистичный, прозрачный, развертывает только Reality за 1 минуту | Нет Hysteria 2, TUIC и Shadowsocks-2022; нет расширенной генерации подписок |
| **MHSanaei/3x-ui** | Go-бинарник + SQLite + Web UI + systemd | Xray-core (с экспериментальной поддержкой sing-box) | VLESS Reality, Trojan, Shadowsocks, WireGuard | Быстрый веб-интерфейс, низкое потребление памяти по сравнению с Python | Привязка преимущественно к Xray; Hysteria 2 и TUIC в sing-box интегрированы через внешние костыли |

---

### 1.2. Сравнительный анализ архитектур: Bash/systemd против Docker Compose

При проектировании `vpn-installer` ключевым решением является выбор фундаментальной среды исполнения ядра:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   АРХИТЕКТУРНАЯ ДИХОТОМИЯ РАЗВЕРТЫВАНИЯ               │
├───────────────────────────────────┬────────────────────────────────────┤
│         Native Systemd            │           Docker Compose           │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Прямой бинарник в /usr/local/bin│ • Контейнер ghcr.io/sagernet/sing-box│
│ • Нулевой оверхед по памяти       │ • Оверхед демона Docker (~50-80 МБ)│
│ • Полный доступ к сети ядра       │ • Изоляция FS, неизменяемый образ  │
│ • Зависимость от glibc/musl OS    │ • Одинаковое поведение на всех OS  │
│ • Ручной менеджмент зависимостей  │ • Чистое удаление/обновление       │
│ • Риск повреждения системных путей│ • Сетевой режим host (zero-nat)    │
└───────────────────────────────────┴────────────────────────────────────┘
```

#### Вариант А: Нативный Systemd
* **Преимущества:**
  - Минимальное использование памяти: на VPS с 512 МБ ОЗУ sing-box потребляет лишь ~25–40 МБ.
  - Прямое взаимодействие с сетевым стеком ядра без прослоек docker-proxy и NAT.
  - Управление через привычный `systemctl {start|stop|restart|status} sing-box` и `journalctl -u sing-box -f`.
* **Недостатки:**
  - Зависимость от пакетного менеджера целевой ОС (разные пути в Ubuntu/Debian, AlmaLinux, Alpine).
  - Сложнее гарантировать откат на предыдущую версию при неудачном обновлении бинарника.
  - При засорении ОС остаточными файлами деинсталляция требует строгого скрипта очистки.

#### Вариант Б: Docker Compose (с `--net=host`)
* **Преимущества:**
  - Идемпотентность и стабильность: образ `ghcr.io/sagernet/sing-box:latest` компилируется разработчиками ядра и протестирован со всеми зависимостями (Go runtime, BoringSSL/quic-go).
  - Безопасность: ядро запускается в изолированной файловой системе в режиме read-only (кроме директорий с логами и кэшем).
  - Автоматизация обновлений через `docker compose pull && docker compose up -d`.
  - Возможность легко расширить стек вспомогательными микросервисами (например, легковесный nginx/caddy для раздачи подписок или node-exporter для метрик).
* **Недостатки:**
  - Требует предварительной установки Docker Engine (~300 МБ дискового пространства и фоновый демон dockerd).
  - Для Hysteria 2 и Reality критически необходим режим `network_mode: "host"`, иначе docker-bridge вносит задержки, дробит UDP-пакеты и ломает определение реальных IP-адресов клиентов.

---

### 1.3. Плюсы, минусы и «подводные камни» существующих скриптов

Анализ кодовой базы скриптов `fscarmen`, `Mack-a` и панелей `Hiddify`/`3x-ui` выявил ряд типичных архитектурных ошибок:

1. **Хаотичная модификация фаервола:** Скрипты массово вызывают `iptables -F` или не очищают за собой цепочки, ломая существующие правила SSH или Docker.
2. **Слепой выбор SNI-домена для Reality:** Использование жестко зашитых доменов (`www.microsoft.com`, `dl.google.com`, `www.yahoo.com`), которые:
   - Либо заблокированы/замедлены ТСПУ в РФ;
   - Либо имеют IP-адреса CDN, отличные от ASN вашего сервера, что легко вскрывается пассивным анализом RTT и эвристиками ТСПУ (разница в задержке между вашим VPS и реальным сервером Microsoft).
3. **Отсутствие валидации портов и конфликтов:** Попытка забиндить порт `443` при работающем на сервере web-сервере (Nginx/Apache/Caddy) без предварительной проверки сокетов приводит к silent failure.
4. **Небезопасное хранение ключей:** Генерация параметров прямо в Bash-переменных без персистентного манифеста. При случайном перезапуске скрипта генерируются новые UUID и Reality Private Keys, что приводит к мгновенной инвалидации настроек у всех клиентов.
5. **DNS-петли (DNS Loops) в sing-box:** Неправильная маршрутизация DNS-запросов самого sing-box через проксирующий outbound, приводящая к 100% загрузке CPU и отказу в обслуживании.

---

## 2. Эталонная серверная конфигурация (Production-Ready Sing-box JSON)

### 2.1. Мультипротокольный `config.json`

Ниже представлена проверенная серверная конфигурация `sing-box` (версий 1.10–1.12+), объединяющая в рамках одного процесса четыре независимых протокола:
1. **VLESS-Reality** (TCP + XTLS-Vision) на стандартном порту `443` (основной stealth-канал для TCP).
2. **Hysteria 2** (модифицированный QUIC/UDP) на порту `8443` с обфускацией `salamander` и поддержкой Port Hopping.
3. **TUIC v5** (QUIC/UDP) на порту `9443` с BBR-контролем перегрузок.
4. **Shadowsocks-2022** (BLAKE3-AES-128-GCM) на порту `8388` (TCP+UDP).

```json
{
  "$schema": "https://raw.githubusercontent.com/SagerNet/sing-box/refs/heads/main/schemas/config/server.json",
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-google",
        "address": "tls://8.8.8.8",
        "address_resolver": "dns-direct"
      },
      {
        "tag": "dns-cloudflare",
        "address": "tls://1.1.1.1",
        "address_resolver": "dns-direct"
      },
      {
        "tag": "dns-direct",
        "address": "local",
        "detour": "direct"
      },
      {
        "tag": "dns-block",
        "address": "rcode://refused"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "dns-direct"
      },
      {
        "clash_mode": "Global",
        "server": "dns-google"
      }
    ],
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": 443,
      "tcp_fast_open": true,
      "sniff": true,
      "sniff_override_destination": false,
      "users": [
        {
          "uuid": "4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f",
          "name": "client-vless-primary",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "gateway.icloud.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "gateway.icloud.com",
            "server_port": 443
          },
          "private_key": "YOUR_REALITY_PRIVATE_KEY_HERE",
          "short_id": [
            "0123456789abcdef",
            "fedcba9876543210"
          ],
          "max_time_difference": "1m"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": 8443,
      "ignore_client_bandwidth": false,
      "users": [
        {
          "name": "client-hy2-primary",
          "password": "HYSTERIA2_STRONG_AUTH_PASSWORD"
        }
      ],
      "obfs": {
        "type": "salamander",
        "password": "SALAMANDER_OBFS_SHARED_SECRET"
      },
      "tls": {
        "enabled": true,
        "server_name": "vpn.your-own-domain.com",
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem",
        "alpn": [
          "h3"
        ]
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 9443,
      "users": [
        {
          "name": "client-tuic-primary",
          "uuid": "4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f",
          "password": "TUIC_STRONG_AUTH_PASSWORD"
        }
      ],
      "congestion_control": "bbr",
      "auth_timeout": "3s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "vpn.your-own-domain.com",
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem",
        "alpn": [
          "h3"
        ]
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-2022-in",
      "listen": "::",
      "listen_port": 8388,
      "network": "tcp+udp",
      "method": "2022-blake3-aes-128-gcm",
      "password": "BASE64_16_BYTE_SERVER_KEY==",
      "users": [
        {
          "name": "client-ss-primary",
          "password": "BASE64_16_BYTE_USER_KEY=="
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "block"
      },
      {
        "protocol": "bittorrent",
        "outbound": "block"
      },
      {
        "port": [
          25,
          465,
          587
        ],
        "outbound": "block"
      }
    ],
    "final": "direct"
  }
}
```

---

### 2.2. Защита от утечек и петель: Inbounds, Outbounds, Route Rules и DNS

Ключевые архитектурные правила построения серверного конфига:

1. **Предотвращение DNS Loops:**
   - На сервере DNS-запросы должны разрешаться через `local` (системный `/etc/resolv.conf`) или явные защищенные апстримы (DoT `tls://8.8.8.8` / `tls://1.1.1.1`).
   - Для резолвера DNS-сервера (`address_resolver`) обязательно указывается `dns-direct` с `detour: "direct"`. В противном случае sing-box пытается отправить DNS-запрос для резолвинга DoT-домена через проксирующий inbound, вызывая глухую блокировку.
2. **Sniffing:**
   - Опция `action: "sniff"` в `route.rules` позволяет серверу извлекать реальный домен из SNI входящих TLS-соединений или HTTP Host заголовка для применения правил маршрутизации.
   - Параметр `sniff_override_destination: false` в inbound Reality гарантирует, что Reality перенаправит трафик точно по адресу целевого назначения, запрошенного клиентом.
3. **Безопасность портов исходящей почты:**
   - Провайдеры VPS (Hetzner, OVH, DigitalOcean, Scaleway) мгновенно блокируют серверы за спам-трафик. Блокировка портов SMTP (`25, 465, 587`) в блоке `route.rules` защищает от случайного абьюза через открытый прокси.

---

### 2.3. Блокировка приватных подсетей, мусорного трафика и BitTorrent

Чтобы предотвратить атаки типа SSRF (Server-Side Request Forgery) на локальные сервисы VPS (например, Docker socket, Redis, metadata API провайдера `169.254.169.254`), а также избежать жалоб правообладателей (DMCA) на торренты:

* **Защита от сканирования локальной сети:**
  ```json
  {
    "ip_is_private": true,
    "outbound": "block"
  }
  ```
  Это правило отсекает запросы к `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` и `169.254.0.0/16`.
* **Защита от торрентов:**
  ```json
  {
    "protocol": "bittorrent",
    "outbound": "block"
  }
  ```
  Встроенный DPI-движок sing-box анализирует хендшейки BitTorrent и дропает пакеты до отправки в публичный интернет хостера.

---

### 2.4. Системная оптимизация ядра Linux (BBR, Fast Open, UDP/TCP сокетные буферы)

Hysteria 2 и TUIC оперируют большими объемами UDP-датаграмм. По умолчанию стек Linux выделяет под сокетные буферы всего 208 КБ (`rmem_default` / `rmem_max`). При передаче видеопотока 4K или всплесках трафика буфер моментально переполняется, ядро сбрасывает пакеты (`UDP buffer errors`), вызывая лавину ретрансмиссий и падение скорости.

#### Эталонный файл `/etc/sysctl.d/99-singbox-network.conf`:

```ini
# Включение BBR и fq qdisc
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open (3 = клиент + сервер одновременно)
net.ipv4.tcp_fastopen = 3

# Увеличение максимального размера очередей сокетов
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192

# Буферы приема и передачи сокетов (максимум 25 МБ для высокоскоростного UDP/QUIC)
net.core.rmem_default = 1048576
net.core.rmem_max = 26214400
net.core.wmem_default = 1048576
net.core.wmem_max = 26214400

# Автоматическая подстройка буферов TCP (min, default, max)
net.ipv4.tcp_rmem = 4096 1048576 26214400
net.ipv4.tcp_wmem = 4096 1048576 26214400

# Разрешение переиспользования TIME_WAIT сокетов
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Защита от переполнения SYN-пакетами
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1

# Разрешение перенаправления пакетов (необходимо для Port Hopping и маршрутизации)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
```

Применение параметров:
```bash
sudo sysctl --system
```

---

## 3. Утилиты и автоматизация генерации криптографических параметров

### 3.1. Встроенные команды `sing-box generate`

Бинарник `sing-box` содержит полный набор криптографических генераторов, исключающий необходимость внешних утилит:

#### 1. Генерация пары ключей X25519 для VLESS-Reality:
```bash
sing-box generate reality-keypair
```
Вывод команды:
```text
PrivateKey: aE4... (32 байта base64)
PublicKey:  kQ9... (32 байта base64)
```
* `PrivateKey` сохраняется в поле `tls.reality.private_key` серверного `config.json`.
* `PublicKey` (`pbk`) передается клиенту в строке подключения `vless://`.

#### 2. Генерация Short ID для Reality:
Команда `rand` генерирует шестнадцатеричные строки заданной байтовой длины (от 1 до 8 байт, то есть 2–16 hex-символов):
```bash
sing-box generate rand --hex 8
# Вывод: 4a2b9e1c7f805d3a
```

#### 3. Генерация UUID (для VLESS и TUIC):
```bash
sing-box generate uuid
# Вывод: f81d4fae-7dec-11d0-a765-00a0c91e6bf6
```

#### 4. Генерация Pre-Shared Key (PSK) для Shadowsocks-2022:
Для шифра `2022-blake3-aes-128-gcm` требуется ровно 16 байт в Base64:
```bash
sing-box generate rand --base64 16
# Вывод: YzBkZTZjNDk1OGY2ZDA5MQ==
```
Для шифров `2022-blake3-aes-256-gcm` и `2022-blake3-chacha20-poly1305` требуется ровно 32 байта в Base64:
```bash
sing-box generate rand --base64 32
```

---

### 3.2. Алгоритм и скрипт валидации маскировочных SNI-доменов

Выбор качественного SNI — критический фактор долговечности VLESS-Reality.

#### Критерии идеального домена маскировки:
1. **Поддержка TLS 1.3:** Обязательное условие протокола Reality.
2. **Поддержка ALPN `h2` (HTTP/2):** ТСПУ в РФ детектирует аномалии, если соединение маскируется под браузер, но не согласовывает HTTP/2.
3. **Совпадение или близость геолокации/ASN:** Идеально, если целевой сервер маскировки находится в том же дата-центре или стране, что и ваш VPS.
4. **Доступность из РФ:** Домен не должен быть внесен в реестр блокировок РКН.
5. **Отсутствие обязательного перенаправления (Redirect 301/302 на сторонние домены)** при хендшейке.
6. **Сертификат от доверенного УЦ:** Домен должен иметь сертификат DigiCert, Let's Encrypt, GTS или Sectigo.

#### Автоматизированный скрипт валидации на Python 3 (`sni_verifier.py`):

```python
#!/usr/bin/env python3
"""
Автоматический валидатор SNI-доменов для VLESS-Reality.
Проверяет поддержку TLS 1.3, ALPN h2, сертификат и замеряет RTT.
"""

import socket
import ssl
import sys
import time

CANDIDATES = [
    "gateway.icloud.com",
    "www.apple.com",
    "swdist.apple.com",
    "mensa.apple.com",
    "dl.google.com",
    "images.unsplash.com",
    "cdn.cloudflare.com",
    "www.speedtest.net",
    "www.samsung.com",
    "update.microsoft.com"
]

def check_sni(domain: str, port: int = 443, timeout: float = 3.0):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    # Требуем минимум TLS 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    start = time.perf_counter()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            tcp_rtt = (time.perf_counter() - start) * 1000
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                total_time = (time.perf_counter() - start) * 1000
                alpn = ssock.selected_alpn_protocol()
                version = ssock.version()
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                common_name = issuer.get("commonName", "Unknown")

                if version == "TLSv1.3" and alpn == "h2":
                    return {
                        "domain": domain,
                        "valid": True,
                        "version": version,
                        "alpn": alpn,
                        "issuer": common_name,
                        "tcp_rtt_ms": round(tcp_rtt, 1),
                        "tls_rtt_ms": round(total_time, 1)
                    }
    except Exception as e:
        return {"domain": domain, "valid": False, "error": str(e)}

    return {"domain": domain, "valid": False, "error": "TLS 1.3 / h2 not satisfied"}

def main():
    print(f"[*] Сканирование кандидатов SNI для Reality...")
    valid_domains = []
    for domain in CANDIDATES:
        res = check_sni(domain)
        if res["valid"]:
            print(f"[+] {domain:<24} | TLS: {res['version']} | ALPN: {res['alpn']} | RTT: {res['tcp_rtt_ms']}ms | CA: {res['issuer']}")
            valid_domains.append(res)
        else:
            print(f"[-] {domain:<24} | Ошибка: {res.get('error')}")

    if not valid_domains:
        print("[!] Не найдено подходящих доменов!")
        sys.exit(1)

    # Выбор домена с наименьшей задержкой
    best = min(valid_domains, key=lambda x: x["tcp_rtt_ms"])
    print(f"\n[★] Рекомендуемый SNI: {best['domain']} (RTT: {best['tcp_rtt_ms']} ms)")

if __name__ == "__main__":
    main()
```

---

### 3.3. Настройка динамического Port Hopping для Hysteria 2 через `iptables` и `nftables`

Провайдеры и ТСПУ часто применяют эвристику «наказания порта»: при обнаружении постоянного высокоскоростного UDP-потока на порту (например, `8443`) порт временно троттлится или блокируется. 

**Port Hopping** позволяет клиенту регулярно (например, каждые 30 секунд) переключать UDP-порт в широком диапазоне (например, `20000:50000`), в то время как сервер перенаправляет весь этот диапазон на локальный порт демона.

```
                     ┌──────────────────────────────────────────────┐
                     │          Сервер Linux (Kernel)               │
Клиент Hysteria 2    │                                              │
(UDP 20000..50000) ──┼──► PREROUTING REDIRECT ──► Внутренний порт   │
  каждые 30 сек      │     (iptables / nftables)       8443 (UDP)   │
                     │                                     │        │
                     │                                     ▼        │
                     │                           sing-box hysteria2 │
                     └──────────────────────────────────────────────┘
```

#### Вариант 1: Через `iptables` (Ubuntu/Debian)

```bash
# Разрешение пересылки
sysctl -w net.ipv4.ip_forward=1

# Перенаправление диапазона портов 20000-50000 UDP на порт инбаунда 8443
sudo iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443
sudo ip6tables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443

# Сохранение правил между перезагрузками
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

#### Вариант 2: Через современный `nftables` (Debian 12, RHEL 9, Alpine)

Файл `/etc/nftables.conf`:
```nft
table inet singbox_nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        udp dport 20000-50000 redirect to :8443
    }
}
```
Применение:
```bash
sudo nft -f /etc/nftables.conf
sudo systemctl enable --now nftables
```

---

## 4. Спецификации клиентских ссылок и форматы подписок

### 4.1. Спецификация `vless://` (Reality + XTLS-Vision)

Формат ссылки:
```text
vless://<UUID>@<SERVER_IP_OR_HOST>:<PORT>?security=reality&encryption=none&pbk=<PUBLIC_KEY>&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=<SNI>&sid=<SHORT_ID>#<REMARKS>
```

#### Описание параметров:
- `<UUID>` — идентификатор пользователя (v4 UUID).
- `security=reality` — активация протокола Reality.
- `encryption=none` — шифрование на уровне VLESS отсутствует (шифрование полностью обеспечивается внешним TLS 1.3).
- `pbk` — публичный ключ сервера X25519 (соответствующий `private_key` сервера).
- `fp=chrome` — имитация TLS ClientHello отпечатка (uTLS fingerprint: `chrome`, `safari`, `ios`, `firefox`). Для РФ строго рекомендуется `chrome`.
- `type=tcp` — транспортный протокол (TCP).
- `flow=xtls-rprx-vision` — оптимизация Vision для устранения TLS-in-TLS паттернов и предотвращения детекции ТСПУ.
- `sni` — домен маскировки (должен совпадать с `handshake.server` на сервере).
- `sid` — один из разрешенных hex Short ID.
- `#<REMARKS>` — отображаемое название узла (URL-encoded).

#### Пример готовой ссылки:
```text
vless://4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f@198.51.100.1:443?security=reality&encryption=none&pbk=kQ9abcdef1234567890abcdef1234567890abcdef12&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=gateway.icloud.com&sid=0123456789abcdef#VLESS-Reality-Vision
```

---

### 4.2. Спецификация `hysteria2://` / `hy2://` (Salamander Obfs, Port Hopping)

Формат ссылки:
```text
hysteria2://<PASSWORD>@<SERVER_IP_OR_HOST>:<PORT>/?sni=<SNI>&obfs=salamander&obfs-password=<OBFS_PWD>&mport=<PORT_RANGE>&insecure=0#<REMARKS>
```

#### Описание параметров:
- `<PASSWORD>` — пароль авторизации пользователя.
- `<PORT>` — базовый порт сервера (например, `8443`).
- `mport` — диапазон портов для Port Hopping (например, `20000-50000`). Клиент периодически выбирает случайный порт из этого списка.
- `obfs=salamander` — тип обфускации датаграмм QUIC.
- `obfs-password` — секретный ключ обфускатора Salamander.
- `insecure=0` — строгая проверка валидности SSL-сертификата (если используется доверенный сертификат Let's Encrypt). Если самоподписанный — `insecure=1`.

#### Пример готовой ссылки:
```text
hysteria2://HYSTERIA2_STRONG_AUTH_PASSWORD@198.51.100.1:8443/?sni=vpn.your-own-domain.com&obfs=salamander&obfs-password=SALAMANDER_OBFS_SHARED_SECRET&mport=20000-50000&insecure=0#Hysteria2-Salamander-Hop
```

---

### 4.3. Спецификация `tuic://` (QUIC, BBR, Congestion Control)

Формат ссылки:
```text
tuic://<UUID>:<PASSWORD>@<SERVER_IP_OR_HOST>:<PORT>/?congestion_control=bbr&alpn=h3&sni=<SNI>&udp_relay_mode=native&allow_insecure=0#<REMARKS>
```

#### Описание параметров:
- `<UUID>:<PASSWORD>` — двойная аутентификация пользователя (спецификация TUIC v5).
- `congestion_control=bbr` — алгоритм контроля перегрузок (`bbr` или `cubic`).
- `alpn=h3` — маскировка под HTTP/3 в TLS-хендшейке.
- `udp_relay_mode=native` — нативная передача UDP через QUIC datagrams.

#### Пример готовой ссылки:
```text
tuic://4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f:TUIC_STRONG_AUTH_PASSWORD@198.51.100.1:9443/?congestion_control=bbr&alpn=h3&sni=vpn.your-own-domain.com&udp_relay_mode=native&allow_insecure=0#TUIC-v5-BBR
```

---

### 4.4. Спецификация `ss://` (Shadowsocks-2022 AEAD / SIP022)

Согласно спецификации SIP022 / Shadowsocks-2022, формат ссылки является человекочитаемым:
```text
ss://<METHOD>:<PASSWORD>@<SERVER_IP_OR_HOST>:<PORT>#<REMARKS>
```
*Примечание: Поскольку пароль в Shadowsocks-2022 является Base64-строкой и может содержать символы `=`, `+` или `/`, они должны быть процентодированы (URL-encoded: `=` → `%3D`, `+` → `%2B`).*

Для обратной совместимости с legacy-клиентами поддерживается формат SIP002 (Base64 от `method:password`):
```text
ss://<BASE64_USERINFO>@<SERVER_IP_OR_HOST>:<PORT>#<REMARKS>
```

#### Пример (SIP022):
```text
ss://2022-blake3-aes-128-gcm:BASE64_16_BYTE_USER_KEY%3D%3D@198.51.100.1:8388#Shadowsocks-2022
```

---

### 4.5. Универсальный формат комплексной подписки

Клиентские приложения (Streisand, v2rayN, FoXray, Sing-box, Clash Verge Rev, Mihomo Party) требуют централизованного получения конфигураций. Существует три основных формата:

#### Формат 1: Plain-Text / Base64 URI List (Универсальный)
Список готовых ссылок, разделенных переводом строки `\n` и закодированных в Base64. Поддерживается 99% мобильных клиентов (V2Box, Streisand, Shadowrocket, Happ, Wings X).

Пример раскодированного тела ответа:
```text
vless://4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f@198.51.100.1:443?security=reality&encryption=none&pbk=kQ9abcdef1234567890abcdef1234567890abcdef12&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=gateway.icloud.com&sid=0123456789abcdef#VLESS-Reality
hysteria2://HYSTERIA2_STRONG_AUTH_PASSWORD@198.51.100.1:8443/?sni=vpn.your-own-domain.com&obfs=salamander&obfs-password=SALAMANDER_OBFS_SHARED_SECRET&mport=20000-50000#Hysteria2
tuic://4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f:TUIC_STRONG_AUTH_PASSWORD@198.51.100.1:9443/?congestion_control=bbr&alpn=h3&sni=vpn.your-own-domain.com#TUIC-v5
ss://2022-blake3-aes-128-gcm:BASE64_16_BYTE_USER_KEY%3D%3D@198.51.100.1:8388#Shadowsocks-2022
```

#### Формат 2: Mihomo (Clash.Meta) YAML Profile
Используется десктопными клиентами (Clash Verge Rev, Mihomo Party, Flclash):

```yaml
port: 7890
socks-port: 7891
mode: rule
log-level: info
ipv6: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
    - 8.8.8.8

proxies:
  - name: "VLESS Reality (Vision)"
    type: vless
    server: 198.51.100.1
    port: 443
    uuid: 4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: gateway.icloud.com
    client-fingerprint: chrome
    reality-opts:
      public-key: kQ9abcdef1234567890abcdef1234567890abcdef12
      short-id: 0123456789abcdef
    udp: true

  - name: "Hysteria 2 (Port-Hop)"
    type: hysteria2
    server: 198.51.100.1
    port: 8443
    ports: 20000-50000
    hop-interval: 30
    password: HYSTERIA2_STRONG_AUTH_PASSWORD
    obfs: salamander
    obfs-password: SALAMANDER_OBFS_SHARED_SECRET
    sni: vpn.your-own-domain.com
    skip-cert-verify: false

  - name: "TUIC v5"
    type: tuic
    server: 198.51.100.1
    port: 9443
    uuid: 4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f
    password: TUIC_STRONG_AUTH_PASSWORD
    udp-relay-mode: native
    congestion-control: bbr
    sni: vpn.your-own-domain.com
    skip-cert-verify: false

  - name: "Shadowsocks-2022"
    type: ss
    server: 198.51.100.1
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: BASE64_16_BYTE_USER_KEY==
    udp: true

proxy-groups:
  - name: "🚀 Авто-Выбор (URL-Test)"
    type: url-test
    proxies:
      - "VLESS Reality (Vision)"
      - "Hysteria 2 (Port-Hop)"
      - "TUIC v5"
      - "Shadowsocks-2022"
    url: 'https://cp.cloudflare.com/generate_204'
    interval: 300

  - name: "PROXY"
    type: select
    proxies:
      - "🚀 Авто-Выбор (URL-Test)"
      - "VLESS Reality (Vision)"
      - "Hysteria 2 (Port-Hop)"
      - "TUIC v5"
      - "Shadowsocks-2022"
      - DIRECT

rules:
  - GEOIP,private,DIRECT
  - GEOIP,RU,DIRECT
  - MATCH,PROXY
```

#### Формат 3: Sing-Box Client Profile JSON
Используется мобильным и десктопным приложением `sing-box` (iOS/Android/macOS/Windows) с нативным TUN-интерфейсом:

```json
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "address": "tls://1.1.1.1",
        "detour": "select-out"
      },
      {
        "tag": "dns-direct",
        "address": "local",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "dns-direct"
      }
    ]
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "sing-tun0",
      "inet4_address": "172.19.0.1/30",
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed",
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "select-out",
      "outbounds": [
        "vless-out",
        "hy2-out",
        "tuic-out",
        "ss-out"
      ],
      "default": "vless-out"
    },
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "198.51.100.1",
      "server_port": 443,
      "uuid": "4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "gateway.icloud.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "kQ9abcdef1234567890abcdef1234567890abcdef12",
          "short_id": "0123456789abcdef"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-out",
      "server": "198.51.100.1",
      "server_port": 8443,
      "server_ports": [
        "20000-50000"
      ],
      "hop_interval": "30s",
      "password": "HYSTERIA2_STRONG_AUTH_PASSWORD",
      "obfs": {
        "type": "salamander",
        "password": "SALAMANDER_OBFS_SHARED_SECRET"
      },
      "tls": {
        "enabled": true,
        "server_name": "vpn.your-own-domain.com"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-out",
      "server": "198.51.100.1",
      "server_port": 9443,
      "uuid": "4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f",
      "password": "TUIC_STRONG_AUTH_PASSWORD",
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "tls": {
        "enabled": true,
        "server_name": "vpn.your-own-domain.com",
        "alpn": [
          "h3"
        ]
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-out",
      "server": "198.51.100.1",
      "server_port": 8388,
      "method": "2022-blake3-aes-128-gcm",
      "password": "BASE64_16_BYTE_USER_KEY=="
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "select-out"
  }
}
```

---

### 4.6. Генерация терминальных и графических QR-кодов (`qrencode`)

Для мгновенного импорта настроек пользователем в мобильное приложение (например, камера телефона сканирует экран терминала):

```bash
# Установка утилиты
sudo apt-get install -y qrencode

# Отображение ANSI-графики в терминале (UTF-8 blocks)
qrencode -t ANSIUTF8 "vless://4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f@198.51.100.1:443?..."

# Экспорт в файл изображения PNG (для веб-панели или отправки в Telegram)
qrencode -o /var/www/sub/vless-qr.png -s 8 -m 2 "vless://..."
```

---

## 5. Рекомендуемая архитектура для `vpn-installer`

### 5.1. Выбор среды развертывания: Docker Compose + официальный образ `ghcr.io/sagernet/sing-box`

На основании проведенного аудита для проекта `vpn-installer` рекомендуется **гибридная модель**:
- **Управление и CLI:** Модульный Bash-скрипт (`installer.sh`) с четким разделением логики (генерация ключей, настройка сети, проверка SNI).
- **Служба прокси:** Docker Compose на базе официального образа `ghcr.io/sagernet/sing-box:latest` с сетевым режимом `host`.

```
/opt/vpn-installer/
├── docker-compose.yml           # Декларативное описание контейнера sing-box
├── manifest.json                # Защищенный манифест учетных данных и ключей (chmod 600)
├── config/
│   └── sing-box.json            # Серверная конфигурация, сгенерированная из манифеста
├── certs/                       # SSL-сертификаты (ACME / Let's Encrypt / self-signed)
│   ├── fullchain.pem
│   └── privkey.pem
├── bin/
│   ├── vpn-cli                  # Симлинк в /usr/local/bin/vpn
│   ├── sni_scanner.py           # Валидатор SNI
│   └── sub_generator.py         # Генератор подписок (Base64, JSON, YAML)
└── web/                         # Легковесный static web server для подписок
    └── index.html
```

#### Образец `docker-compose.yml`:
```yaml
services:
  sing-box:
    image: ghcr.io/sagernet/sing-box:latest
    container_name: sing-box-vpn
    restart: always
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config/sing-box.json:/etc/sing-box/config.json:ro
      - ./certs:/etc/sing-box/certs:ro
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

### 5.2. Модель хранения состояния и учетных данных (`manifest.json`)

Все параметры сессии должны сохраняться в персистентный файл состояния с правами доступа `600`. Это гарантирует, что повторные запуски инсталлятора, добавление пользователей или смена портов не перегенерируют существующие криптографические ключи клиентов.

```json
{
  "version": "1.0.0",
  "created_at": "2026-11-10T02:00:00Z",
  "server": {
    "ipv4": "198.51.100.1",
    "ipv6": "2001:db8::1",
    "domain": "vpn.your-own-domain.com"
  },
  "protocols": {
    "vless_reality": {
      "enabled": true,
      "port": 443,
      "sni": "gateway.icloud.com",
      "private_key": "YOUR_REALITY_PRIVATE_KEY",
      "public_key": "YOUR_REALITY_PUBLIC_KEY",
      "short_ids": ["0123456789abcdef", "fedcba9876543210"]
    },
    "hysteria2": {
      "enabled": true,
      "port": 8443,
      "port_hopping": {
        "enabled": true,
        "range": "20000:50000"
      },
      "obfs_password": "SALAMANDER_OBFS_SHARED_SECRET"
    },
    "tuic": {
      "enabled": true,
      "port": 9443,
      "congestion_control": "bbr"
    },
    "shadowsocks_2022": {
      "enabled": true,
      "port": 8388,
      "method": "2022-blake3-aes-128-gcm",
      "server_key": "BASE64_16_BYTE_SERVER_KEY=="
    }
  },
  "users": [
    {
      "id": "u-admin-01",
      "name": "admin",
      "uuid": "4f9c5d1a-6e2b-4c3d-8f5a-7e9d1c3b5a7f",
      "passwords": {
        "hy2": "HYSTERIA2_STRONG_AUTH_PASSWORD",
        "tuic": "TUIC_STRONG_AUTH_PASSWORD",
        "ss": "BASE64_16_BYTE_USER_KEY=="
      },
      "subscription_token": "sub_a9f8b2c7e1d440938b8c2fa8e9d"
    }
  ]
}
```

---

### 5.3. Механизм выдачи ссылок и обновлений конфигураций

Для удобства пользователя предлагается два сценария выдачи конфигураций:

1. **CLI Output (Интерактивный):**
   Команда `vpn show` выводит в терминал текстовые URI-ссылки и генерирует QR-коды прямо в консоли для каждого протокола:
   ```bash
   vpn show --user admin --protocol reality --qr
   vpn show --all
   ```

2. **Защищенная HTTP-ссылка на подписку (Dynamic Subscription):**
   - На сервере поднимается легковесный HTTP-сервис (на базе встроенного в sing-box `inbound` типа `v2ray-api` или микро-веб-сервера), слушающий случайный закрытый порт или path.
   - Ссылка формируется с криптографическим токеном:
     `https://vpn.your-own-domain.com/sub/sub_a9f8b2c7e1d440938b8c2fa8e9d`
   - Сервер анализирует HTTP-заголовок `User-Agent`:
     - Если обращается `ClashMeta` / `Mihomo` / `ClashVerge` → отдается YAML-конфигурация.
     - Если обращается `sing-box` → отдается полный JSON-профиль.
     - Для всех остальных (браузер, Streisand, Shadowrocket, V2Box) → отдается Base64-список URI.

---

### 5.4. Жизненный цикл, мониторинг и процедура автообновления

1. **Идемпотентный установщик:**
   - Повторный запуск скрипта `installer.sh` проверяет наличие `/opt/vpn-installer/manifest.json`.
   - Если файл существует, предлагается меню обслуживания: «Добавить пользователя», «Сменить SNI Reality», «Перезапустить сервис», «Обновить ядро», «Удалить VPN».
2. **Бесшовное обновление ядра:**
   ```bash
   docker compose pull sing-box
   docker compose up -d sing-box
   ```
3. **Мониторинг:**
   Контейнер проверяет синтаксис конфига перед перезагрузкой:
   ```bash
   docker run --rm -v /opt/vpn-installer/config/sing-box.json:/config.json ghcr.io/sagernet/sing-box:latest check -c /config.json
   ```

---

## 6. Библиография, спецификации и первичные репозитории

1. **Официальный репозиторий ядра sing-box:**  
   https://github.com/SagerNet/sing-box  
   *Документация:* https://sing-box.sagernet.org/

2. **Спецификация и репозиторий Xray-core (VLESS, XTLS-Reality, Vision):**  
   https://github.com/XTLS/Xray-core  
   *RealiTLScanner:* https://github.com/XTLS/RealiTLScanner

3. **Спецификация Hysteria 2 (Salamander Obfuscation & Port Hopping):**  
   https://github.com/apernet/hysteria  
   *Документация протокола:* https://v2.hysteria.network/

4. **Спецификация TUIC v5:**  
   https://github.com/EAimTY/tuic

5. **Спецификации Shadowsocks-2022 (SIP022 / SIP023):**  
   https://github.com/shadowsocks/shadowsocks-org/wiki/Shadowsocks-2022-Specification

6. **Ядро Mihomo (Clash.Meta):**  
   https://github.com/MetaCubeX/mihomo  
   *Документация конфигурации:* https://wiki.metacubex.one/

7. **Анализ открытых решений автоматизации:**
   - `chika0801/sing-box-examples`: https://github.com/chika0801/sing-box-examples
   - `fscarmen/sing-box`: https://github.com/fscarmen/sing-box
   - `hiddify/Hiddify-Manager`: https://github.com/hiddify/Hiddify-Manager
   - `Gozargah/Marzban`: https://github.com/Gozargah/Marzban
   - `Mack-a/v2ray-agent`: https://github.com/Mack-a/v2ray-agent
   - `233boy/sing-box`: https://github.com/233boy/sing-box
