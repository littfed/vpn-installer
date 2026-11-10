# Архитектура Self-Hosted DNS, DoT/DoH/DoQ и избирательной маршрутизации в Sing-box и AmneziaWG

> **Статус документа:** Исследовательский и инженерный отчет (Production Blueprint)  
> **Версии ПО:** Sing-box v1.10+ / v1.11+, AdGuard Home v0.107+, Unbound 1.20+, CoreDNS 1.11+, AmneziaWG 1.0+, Caddy v2.8+  
> **Область применения:** Обход цензуры ТСПУ/РКН, устранение DNS-спуфинга, раздельная маршрутизация (Split-DNS), доступ к зарубежным ИИ-сервисам, блокировка рекламы и защита приватности.

---

## 1. Архитектурный обзор и исполнительное резюме (Executive Summary)

### 1.1. Проблематика DNS в условиях агрессивного DPI (ТСПУ)

В современной инфраструктуре фильтрации трафика в РФ система разрешения доменных имен (DNS) является первичным рубежом цензуры и слежки. Технические средства противодействия угрозам (ТСПУ), установленные на узлах операторов связи согласно закону «о суверенном Рунете», реализуют комплекс деструктивных воздействий на стандартный трафик DNS:
1. **DNS Poisoning (UDP 53 In-line Injection):** ТСПУ осуществляет пассивный перехват UDP-запросов на порт 53. При совпадении запрашиваемого FQDN с реестром запрещенных сайтов РКН или сигнатурным списком ТСПУ генерирует опережающий поддельный DNS-ответ (DNS Response Spoofing) с адресом заглушки провайдера или `127.0.0.1` до прихода легитимного ответа от внешнего резолвера.
2. **Transparent Port 53 Redirection & Hijacking:** Попытки обращения к сторонним публичным DNS-серверам (например, `8.8.8.8`, `1.1.1.1`) принудительно перехватываются операторскими шлюзами и направляются на внутренние цензурирующие резолверы оператора связи.
3. **Блокировка и деградация стандартных защищенных протоколов:**
   - Стандартный порт DoT (DNS-over-TLS, TCP 853) подвергается регулярным веерным блокировкам и сбросам TCP RST со стороны ТСПУ.
   - Популярные публичные эндпоинты DoH (Cloudflare `1.1.1.1/dns-query`, Google `dns.google`) периодически блокируются по IP и SNI, либо подвергаются искусственному ограничению пропускной способности (throttling) и отсечению флагов ECH (Encrypted Client Hello).
4. **Утечки метаданных и геолокации через EDNS0 Client Subnet (ECS):** Передача реального IP-префикса клиента авторитетным серверам приводит к гео-блокировке со стороны зарубежных сервисов (OpenAI, Anthropic, Claude, Spotify) и деанонимизации конечной инфраструктуры пользователя.

### 1.2. Цели и задачи архитектуры Split-DNS

Для обеспечения стабильной работы клиентских устройств требуется реализация гибридного контура разрешения имен (**Split-DNS**), удовлетворяющего четырем взаимоисключающим требованиям:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           ТОПОЛОГИЯ МУЛЬТИ-СЕГМЕНТНОГО SPLIT-DNS                                │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │ Запрос DNS от приложения / ОС
                                                 ▼
                             ┌──────────────────────────────────────┐
                             │       Маршрутизатор DNS Клиента      │
                             │  (Sing-box DNS Core / Router DNS)    │
                             └───────────────────┬──────────────────┘
                                                 │
         ┌───────────────────────────────────────┼──────────────────────────────────────┐
         │ Сегмент 1: RU Direct                  │ Сегмент 2: Censored / Foreign / AI   │ Сегмент 3: AdBlock / Sec
         ▼                                       ▼                                      ▼
┌─────────────────────────────┐         ┌─────────────────────────────┐        ┌─────────────────────────────┐
│ Домены: *.ru, *.рф, *.su,   │         │ Домены: YouTube, Instagram, │        │ Домены: телеметрия, трекеры,│
│ Госуслуги, Банки РФ, VK, Ya │         │ OpenAI, Claude, Twitter, FB │        │ вредоносное ПО, баннеры     │
├─────────────────────────────┤         ├─────────────────────────────┤        ├─────────────────────────────┤
│ Резолвер: Domestic DNS      │         │ Резолвер: Self-Hosted DoH   │        │ Резолвер: AdGuard Home      │
│ (Yandex 77.88.8.8 / ISP)    │         │ / Unbound через Прокси      │        │ Filtering Engine (Null IP)  │
├─────────────────────────────┤         ├─────────────────────────────┤        ├─────────────────────────────┤
│ Egress: Напрямую (Direct)   │         │ Egress: VLESS-Reality/WARP  │        │ Egress: Локальный Drop      │
├─────────────────────────────┤         ├─────────────────────────────┤        ├─────────────────────────────┤
│ Результат: Минимальный RTT, │         │ Результат: Отсутствие спуфа,│        │ Результат: 0 байт рекламы,  │
│ легитимные IP для CDN РФ    │         │ чистые зарубежные IP CDN    │        │ экономия полосы пропускания │
└─────────────────────────────┘         └─────────────────────────────┘        └─────────────────────────────┘
```

1. **Сегмент RU Direct (Внутрироссийский трафик):** Ресурсы в зоне `.ru`, `.su`, `.рф`, правительственные и банковские порталы должны резолвиться через быстрые внутрироссийские DNS-серверы без проксирования. Это исключает блокировки по зарубежным IP (Geoblocking российских сервисов), предотвращает задержки маршрутизации и обеспечивает доступ к сервисам, подписанным сертификатами Национального удостоверяющего центра (НУЦ Минцифры).
2. **Сегмент Bypassed / Censored / AI (Заблокированные и ИИ-сервисы):** Ресурсы, ограниченные РКН или блокирующие запросы из РФ (OpenAI, Anthropic, Google Gemini), должны резолвиться исключительно через защищенный закрытый канал (DoH/DoT через туннель VLESS-Reality, ShadowTLS или WARP Egress). DNS-ответы должны содержать IP-адреса ближайших к egress-ноде точек присутствия зарубежных CDN (Anycast/Unicast).
3. **Сегмент AdBlock & Tracking Protection:** Централизованная фильтрация рекламных сетей, трекеров и вредоносных фишинговых доменов на этапе резолвинга с минимальными накладными расходами памяти.
4. **Защита от утечек DNS (DNS Leak Prevention):** Полное исключение параллельных fallback-запросов через системные интерфейсы ОС, предотвращающее перехват трафика сенсорами ТСПУ.

---

## 2. Сравнительный анализ стеков Self-Hosted DNS

Для развертывания на ноде под управлением Linux доступны три ключевые архитектурные модели: AdGuard Home, связка Unbound + CoreDNS, и встроенный DNS-движок Sing-box.

### 2.1. AdGuard Home

**AdGuard Home** представляет собой специализированный высокопроизводительный локальный кэширующий DNS-сервер с функциями глубокой фильтрации, переопределения ответов (Rewrites) и поддержкой всех современных шифрованных протоколов DNS.

#### Ключевые возможности:
- **Широкий спектр протоколов шифрования:** Нативная поддержка DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250), DNSCrypt и DNS-over-HTTPS/3 (QUIC).
- **Гибкая селективная маршрутизация апстримов:** Поддержка синтаксиса условных апстримов на базе доменных паттернов:
  ```yaml
  # Направление российских зон на локальный сервер Yandex DNS
  [/ru/]77.88.8.8
  [/su/]77.88.8.8
  [/xn--p1ai/]77.88.8.8
  [/gosuslugi.ru/]77.88.8.8
  # Направление остальных запросов на защищенный апстрим Cloudflare DoT
  tls://1.1.1.1
  ```
- **EDNS Client Subnet (ECS) управление:** Возможность полного отключения отправки ECS (`edns.client.enabled: false`) либо подмены отправляемой подсети на анонимную/зарубежную. Это критично для предотвращения передачи информации о российском провайдере зарубежным авторитетным серверам.
- **DNS Rewrite Engine:** Локальное статическое назначение записей (A, AAAA, CNAME) для обхода CDN-банов и фиксации IP конкретных серверов.

#### Эталонная конфигурация `AdGuardHome.yaml` (Production-Hardened):

```yaml
bind_host: 0.0.0.0
bind_port: 3000
beta_bind_port: 0
users:
  - name: admin
    # Хэш пароля bcrypt (генерируется утилитой htpasswd или встроенным мастером)
    password: $2y$10$E0s7Q6R.tF09GZvhWv3rreG1Fv7uI3FfK.C84tqZ4x7m8p2nF/EOW

dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  
  # Защита от истощения ресурсов и DoS-атак
  ratelimit: 300
  ratelimit_whitelist:
    - 127.0.0.1
    - 10.8.0.0/24
    - 172.29.172.0/24

  # Список апстримов с условной маршрутизацией
  upstream_dns:
    # Российские домены направляются на чистые внутренние DNS без задержки
    - "[/ru/]77.88.8.8"
    - "[/xn--p1ai/]77.88.8.8"
    - "[/su/]77.88.8.8"
    - "[/gosuslugi.ru/]77.88.8.8"
    - "[/sberbank.ru/]77.88.8.8"
    - "[/tbank.ru/]77.88.8.8"
    - "[/yandex.ru/]77.88.8.8"
    - "[/vk.com/]77.88.8.8"
    # Международные защищенные апстримы по протоколам DoT и DoH
    - "tls://dns.quad9.net"
    - "https://dns.cloudflare.com/dns-query"
    - "quic://dns.adguard-dns.com"

  # Режим параллельного опроса всех апстримов для минимизации задержки
  all_servers: true
  fastest_addr: true

  # Резервные серверы на случай падения основных каналов
  fallback_dns:
    - 9.9.9.9
    - 1.1.1.1

  # Настройка кэширования в оперативной памяти
  cache_size: 67108864 # 64 MB кэша
  cache_ttl_min: 300   # Минимальный TTL 5 минут (снижает количество сетевых запросов)
  cache_ttl_max: 86400 # Максимальный TTL 24 часа
  cache_optimistic: true # Возврат устаревшей записи из кэша с асинхронным обновлением

  # Приватность и защита от утечек
  anonymize_client_ip: true
  edns_client_subnet:
    enabled: false # Полное вырезание ECS для защиты геопозиции клиента
    use_custom: false

  # Валидация DNSSEC на стороне сервера
  dnssec: true

  # Блокировка IPv6 для предотвращения утечек через ненастроенные IPv6-туннели
  block_ipv6: true

tls:
  enabled: true
  server_name: dns.node-internal.net
  force_https: false
  port_https: 8443 # Внутренний порт для проксирования через Caddy/Nginx
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  certificate_path: /opt/certs/fullchain.pem
  private_key_path: /opt/certs/privkey.pem

filtering:
  blocking_mode: null_ip
  blocked_response_ttl: 10
  protection_enabled: true
  filtering_enabled: true

# Оптимизированные списки блокировки рекламы и трекеров
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: "AdGuard Base Filter"
    id: 1
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
    name: "AdGuard Tracking Protection"
    id: 2
  - enabled: true
    url: https://big.oisd.nl
    name: "OISD Big"
    id: 3
```

---

### 2.2. CoreDNS и Unbound

В инфраструктуре корпоративного уровня или при повышенных требованиях к автономности применяется разделение ролей:
- **CoreDNS:** Быстрый фронтенд-прокси и селектор запросов с расширяемой архитектурой плагинов.
- **Unbound:** Полноценный локальный итеративный рекурсивный резолвер (Recursive Validating Resolver), напрямую опрашивающий корневые серверы DNS (`root-hints`) и авторитетные серверы зон TLD.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      АРХИТЕКТУРА СВЯЗКИ COREDNS + UNBOUND                       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ DNS Query
                                         ▼
                            ┌────────────────────────┐
                            │   CoreDNS (Edge DNS)   │
                            │   Port 53 / 853 (DoT)  │
                            └────────────┬───────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │ (*.ru, *.рф)                                  │ (Все остальные запросы)
                 ▼                                               ▼
     ┌───────────────────────┐                       ┌───────────────────────┐
     │  Upstream Domestic    │                       │  Unbound (Recurser)   │
     │  (77.88.8.8:53)       │                       │  Port 5335 (Loopback) │
     └───────────────────────┘                       └───────────┬───────────┘
                                                                 │
                                                 ┌───────────────┼───────────────┐
                                                 ▼               ▼               ▼
                                           Root Hints (.)    TLD (.com)     Authoritative
                                           [QNAME Min]       [QNAME Min]     [DNSSEC OK]
```

#### Сравнение Unbound и сторонних DoH/DoT провайдеров:
1. **Автономность и отсутствие доверия третьим сторонам:** Unbound не отправляет трафик Cloudflare, Google или Quad9. Он производит прямую итеративную резолюцию: `.` -> `.com` -> `example.com`. Провайдеры публичных DNS не могут профилировать пользователя.
2. **QNAME Minimization (RFC 7816 / RFC 9156):** Рекурсивный резолвер отправляет на корневые серверы только минимально необходимый фрагмент имени. Для запроса `api.openai.com` корневой сервер видит запрос зоны `.com`, сервер зоны `.com` видит запрос `openai.com`, и только конечный авторитетный сервер `ns1.openai.com` видит полный FQDN `api.openai.com`.
3. **Строгая валидация DNSSEC (RFC 4033, 4034, 4035):** Unbound криптографически проверяет RRSIG-подписи с использованием доверенного корня ICANN, полностью исключая подмену записей по пути следования.

#### Конфигурация `unbound.conf` (Hardened Recursive):

```text
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    # Контроль доступа (разрешен только локальный хост и внутренние контейнеры)
    access-control: 127.0.0.1/32 allow
    access-control: 172.16.0.0/12 allow
    access-control: 10.0.0.0/8 allow

    # Защита приватности: QNAME Minimization (RFC 9156)
    qname-minimisation: yes
    qname-minimisation-strict: no

    # Защита от подделки идентификаторов (0x20 encoding)
    use-caps-for-id: yes

    # Валидация DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no

    # Защита кэша и оптимизация памяти
    infra-cache-numhosts: 10000
    msg-cache-size: 64m
    rrset-cache-size: 128m
    key-cache-size: 32m
    neg-cache-size: 16m

    # Упреждающее обновление популярных записей до истечения TTL
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-client-timeout: 1800

    # Агрессивное NSEC-кэширование (RFC 8198) для минимизации спама NXDOMAIN
    aggressive-nsec: yes

    # Удаление идентификаторов сервера и приватность метаданных
    hide-identity: yes
    hide-version: yes
    identity: "DNS"
```

#### Конфигурация `Corefile` (CoreDNS с маршрутизацией):

```text
.:53 {
    bind 0.0.0.0
    
    # Логирование ошибок и мониторинг Prometheus
    errors
    prometheus 0.0.0.0:9153
    
    # Защита от перегрузок
    ratelimit {
        rate 100
        burst 200
    }

    # Селектор: российские домены направляются на Yandex DNS
    @ru_zones {
        domain ru su xn--p1ai
    }
    forward @ru_zones 77.88.8.8 77.88.8.1 {
        prefer_udp
        max_fails 3
    }

    # Остальной трафик направляется на локальный рекурсивный Unbound
    forward . 127.0.0.1:5335 {
        except ru su xn--p1ai
        health_check 5s
    }

    cache 3600 {
        success 10000
        denial 2000
        prefetch 5 30m
    }
    
    reload 30s
}
```

---

### 2.3. Встроенный DNS-сервер Sing-box (Inbound DNS)

Начиная с ветки v1.8+ и вплоть до актуальных версий v1.10–v1.11+, ядро `sing-box` содержит встроенную реализацию полнофункционального DNS-сервера. Она позволяет ноде выступать в качестве автономного DoH/DoT/UDP-сервера разрешения имен для внешних клиентов без развертывания дополнительных демонов.

#### Конфигурация Inbound DNS в Sing-box:

```json
{
  "inbounds": [
    {
      "type": "dns",
      "tag": "dns-in",
      "listen": "0.0.0.0",
      "listen_port": 53
    },
    {
      "type": "direct",
      "tag": "dns-dot-in",
      "listen": "0.0.0.0",
      "listen_port": 853,
      "tls": {
        "enabled": true,
        "server_name": "dns.example.com",
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
  ]
}
```

Все запросы, поступившие во входящий `dns-in`, мгновенно попадают во внутренний DNS-маршрутизатор блока `dns.rules`, где маршрутизируются согласно сконфигурированным апстримам и выходным шлюзам (outbounds).

---

## 3. Архитектура конечных точек DoT и DoH: Развертывание и мультиплексирование портов

### 3.1. Порты, протоколы и сигнатурная маскировка

| Протокол | Порт / Транспорт | Стандарт RFC | Статус блокировки ТСПУ в РФ | Архитектурная роль |
|---|---|---|---|---|
| **Plain DNS** | 53 UDP / TCP | RFC 1035 | **Тотальный перехват и спуфинг** | Исключительно локальная связь `127.0.0.1` |
| **DoT (DNS over TLS)** | 853 TCP | RFC 7858 | **Регулярные веерные блокировки** | Канал между серверами / Внутритунельный DNS |
| **DoH (DNS over HTTPS)** | 443 TCP (HTTP/2) | RFC 8484 | **Скрыт внутри общего HTTPS** | Основной клиентский канал через Caddy |
| **DoH3 (DoH over HTTP/3)**| 443 UDP (QUIC) | RFC 9114 / RFC 9250 | **Высокая устойчивость** (0-RTT) | Мобильные клиенты, борьба с packet loss |
| **DoQ (DNS over QUIC)** | 853 UDP | RFC 9250 | Блокируется вместе с портом 853 | Экспериментальный, для прямого AdGuard |

> [!IMPORTANT]
> Использование стандартного порта 853 для клиентского подключения из РФ является ненадежным решением: ТСПУ непрерывно сбрасывает TCP-сессии на порт 853 независимо от SNI.  
> **Единственным устойчивым публичным решением является DoH на стандартном порту TCP 443 с мультиплексированием через Reverse Proxy (Caddy/Nginx) и сокрытием эндпоинта за нестандартным секретным URI.**

---

### 3.2. Мультиплексирование порта 443: Caddy Reverse Proxy + Decoy Site

На ноде `vpn-installer` порт 443 TCP/UDP используется для обслуживания маскировочного сайта (Decoy Site). Конфигурация веб-сервера Caddy позволяет терминировать TLS для доменного имени ноды, отдавать легитимный веб-контент для любых веб-сканеров и цензоров по пути `/`, но прозрачно проксировать запросы к `/dns-query` (или секретному пути `/v1/secure-dns-endpoint`) на локальный бэкенд AdGuard Home по протоколу HTTP/2 и HTTP/3.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 ПУБЛИЧНЫЙ КАНАЛ (WAN)                   │
                  └────────────────────────────┬────────────────────────────┘
                                               │ TCP/UDP Port 443 (TLS 1.3 + HTTP/3)
                                               ▼
                             ┌───────────────────────────────────┐
                             │       Caddy Edge Web Server       │
                             │  (Auto-HTTPS via Let's Encrypt)   │
                             └─────────────────┬─────────────────┘
                                               │
                      ┌────────────────────────┴────────────────────────┐
                      │ Path: /                                         │ Path: /dns-query
                      ▼                                                 ▼
          ┌───────────────────────┐                         ┌───────────────────────┐
          │   Decoy Site (HTML)   │                         │ AdGuard Home Backend  │
          │   (Authentic Website) │                         │ (127.0.0.1:8053 HTTP) │
          └───────────────────────┘                         └───────────────────────┘
```

#### Конфигурация `Caddyfile`:

```caddy
{
    # Включение поддержки HTTP/3 (QUIC) на UDP 443
    servers {
        protocol {
            experimental_http3
        }
    }
    email admin@example.com
}

dns.example.com {
    # Терминация TLS с поддержкой современных шифров
    tls {
        protocols tls1.2 tls1.3
        ciphers TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256
    }

    # Маскировочный сайт для предотвращения блокировок по HTTP-пробингу
    root * /usr/share/caddy/html
    file_server

    # Проксирование DoH-запросов на внутренний порт AdGuard Home
    @doh {
        path /dns-query
        path /v1/doh-secret-query
        header Content-Type application/dns-message
    }

    handle @doh {
        reverse_proxy 127.0.0.1:8053 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}

            # Настройка буферизации для минимизации задержек DNS
            flush_interval -1
            transport http {
                keepalive 30s
                compression off
            }
        }
    }

    # Защитные заголовки
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}
```

---

### 3.3. Готовый шаблон развертывания Docker Compose

Интеграция стека DNS в существующую ноду `vpn-installer` выполняется с изоляцией сервисов в единой внутренней сети `vpn-net`.

#### Файл `docker-compose.dns.yml`:

```yaml
version: "3.8"

networks:
  vpn-net:
    name: vpn-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

services:
  # Полноценный рекурсивный резолвер с защитой QNAME Minimization
  unbound:
    image: mvance/unbound:latest
    container_name: dns-unbound
    restart: unless-stopped
    networks:
      vpn-net:
        ipv4_address: 172.28.0.2
    volumes:
      - ./unbound/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro
    healthcheck:
      test: ["CMD-SHELL", "drill @127.0.0.1 -p 5335 cloudflare.com || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Бэкенд фильтрации и управления DNS
  adguard:
    image: adguard/adguardhome:v0.107.54
    container_name: dns-adguard
    restart: unless-stopped
    networks:
      vpn-net:
        ipv4_address: 172.28.0.3
    ports:
      # Локальный plain DNS для WireGuard/AmneziaWG шлюза
      - "127.0.0.1:53:53/udp"
      - "127.0.0.1:53:53/tcp"
      - "10.8.0.1:53:53/udp"
      - "10.8.0.1:53:53/tcp"
      # Внутренний порт DoH для проксирования Caddy
      - "127.0.0.1:8053:8053/tcp"
      # Веб-панель управления
      - "127.0.0.1:3000:3000/tcp"
    volumes:
      - ./adguard/work:/opt/adguardhome/work
      - ./adguard/conf:/opt/adguardhome/conf
    depends_on:
      - unbound
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Фронтенд веб-сервер Caddy (Reverse Proxy + Decoy Site)
  caddy:
    image: caddy:2.8.4-alpine
    container_name: caddy-edge
    restart: unless-stopped
    networks:
      vpn-net:
        ipv4_address: 172.28.0.4
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "443:443/udp" # HTTP/3 QUIC
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/html:/usr/share/caddy/html:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
    depends_on:
      - adguard
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## 4. Подсистема DNS в Sing-box (v1.10+ / v1.11+)

Подсистема `dns` в Sing-box представляет собой автономный таблично-ориентированный маршрутизатор, функционирующий до уровня L3-маршрутизации трафика.

### 4.1. Внутренняя архитектура и жизненный цикл запроса

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        ЖИЗНЕННЫЙ ЦИКЛ DNS В SING-BOX                            │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ DNS Query
                                         ▼
                            ┌────────────────────────┐
                            │    DNS Cache Check     │ ◄─── [independent_cache: true]
                            └────────────┬───────────┘
                                         │ Cache Miss
                                         ▼
                            ┌────────────────────────┐
                            │   dns.rules Evaluation │
                            │   (Aho-Corasick Tree)  │
                            └────────────┬───────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 │ rule_set: geosite-ru  │ rule_set: geosite-ai  │ Default / Final
                 ▼                       ▼                       ▼
     ┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
     │ server: dns-ru        │ │ server: dns-remote    │ │ server: dns-adguard   │
     │ detour: direct        │ │ detour: proxy (VLESS) │ │ detour: direct / vpn  │
     └───────────┬───────────┘ └───────────┬───────────┘ └───────────┬───────────┘
                 │                       │                           │
                 ▼                       ▼                           ▼
     [Bootstrap address]         [address_resolver]          [address_resolver]
     Local Interface             Tunnel Routing              Direct IP
```

#### Ключевые параметры блока `dns`:
- `servers`: Массив определений вышестоящих DNS-серверов.
  - `tag`: Уникальный идентификатор сервера.
  - `address`: URI резолвера (`https://...`, `tls://...`, `udp://...`, `local`, `rcode://refused`).
  - `address_resolver`: Тег сервера, используемого для разрешения доменного имени самого DoH-хоста (устраняет циклическую зависимость bootstrap).
  - `address_strategy`: Стратегия резолвинга хоста (`prefer_ipv4`, `prefer_ipv6`, `ipv4_only`).
  - `strategy`: Стратегия возврата записей клиенту (`prefer_ipv4`, `ipv4_only`).
  - `detour`: Тег сетевого outbound, через который физически отправляются сетевые пакеты DNS-запроса (`direct`, `proxy-vless`, `warp-out`).
  - `client_subnet`: Параметр для форсирования или вырезания ECS (например, `198.51.100.0/24` или `0.0.0.0/0`).
- `rules`: Массив правил классификации запросов. Правила вычисляются строго сверху вниз до первого совпадения.
- `independent_cache`: Булево значение (`true`). Разделяет кэш DNS по каждому сетевому outbound, предотвращая отравление кэша прямого соединения поддельными записями или некорректными CDN IP.
- `reverse_mapping`: Булево значение (`true`). Автоматически сопоставляет IP-адреса из DNS-ответов с исходными доменными именами. Позволяет L3-роутеру маршрутизировать трафик по доменным правилам даже в тех случаях, когда приложение обращается напрямую по IP-адресу без передачи SNI.

---

### 4.2. Синтаксис сопоставления доменов и бинарные Rule-Sets (`.srs`)

Sing-box поддерживает четыре базовых доменных примитива и скомпилированные бинарные базы:
1. `domain`: Полное точное совпадение FQDN (например, `api.openai.com`).
2. `domain_suffix`: Совпадение по суффиксу и поддоменам (например, `.ru`, `openai.com`).
3. `domain_keyword`: Поиск подстроки в любой части доменного имени.
4. `domain_regex`: Сопоставление по регулярному выражению PCRE.
5. `rule_set`: Высокопроизводительные компилированные наборы правил в формате `.srs` (Sing-box Rule Set).

#### Преимущества `.srs` над JSON:
Бинарный формат `.srs` представляет собой предварительно скомпилированное дерево поиска (Aho-Corasick / Radix Tree). При объеме базы в 100 000+ доменов (например, полный реестр РКН) парсинг JSON занимает секунды и сотни мегабайт RAM. Загрузка `.srs` происходит практически мгновенно посредством системного вызова `mmap` с минимальным потреблением оперативной памяти (менее 15 МБ).

---

### 4.3. Архитектурная дуэль: FakeIP (`fakeip`) vs RealIP

В клиентском режиме Inbound TUN ключевым архитектурным решением является выбор между FakeIP и RealIP.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   СРАВНЕНИЕ FAKEIP И REALIP                                      │
├────────────────────────────────┬────────────────────────────────┬────────────────────────────────┤
│ Критерий                       │ FakeIP (tun.fakeip)            │ RealIP (Real DNS Resolution)   │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Механика работы**            │ Ядро немедленно выдает IP из   │ Ядро отправляет реальный       │
│                                │ пула 198.18.0.0/15 с TTL=1s.   │ запрос на удаленный резолвер,  │
│                                │ Запрос в интернет не идет!     │ ждет ответа и отдает реальный  │
│                                │ При TCP Handshake ядро берет   │ IP клиенту.                    │
│                                │ домен из `fakeip-store`.       │                                │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Задержка резолвинга (RTT)**  │ **0 мс (мгновенно)**           │ 50–250 мс (зависит от пинга до │
│                                │                                │ прокси и удаленного DNS).      │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Утечки DNS (DNS Leaks)**     │ **Полностью исключены** на     │ Возможны при падении туннеля   │
│                                │ уровне архитектуры операционки.│ или параллельном системном DNS.│
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Зависимость от CDN Egress**  │ Автоматически выбирается CDN   │ Зависит от совпадения EDNS     │
│                                │ IP, ближайший к выходу прокси. │ адреса с реальным выходом.     │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Совместимость с софтом**     │ Могут сбоить утилиты, требующие│ 100% совместимость со всеми    │
│                                │ валидного внешнего IP (traceroute,│ сетевыми утилитами.         │
│                                │ чистый ICMP ping, старые игры).│                                │
└────────────────────────────────┴────────────────────────────────┴────────────────────────────────┘
```

> [!TIP]
> Для мобильных устройств и десктопных рабочих станций в РФ **рекомендуется использовать FakeIP**. Это полностью устраняет задержку первого открытия страниц, предотвращает любые DNS-утечки мимо туннеля и защищает от отравления DNS-кэша операционной системы со стороны ТСПУ.

---

### 4.4. Эталонный клиентский конфиг Sing-box (Production-Ready)

Представленная конфигурация реализует:
- Входящий TUN-адаптер с поддержкой FakeIP (`198.18.0.0/15`).
- Автономный мульти-сегментный DNS:
  - Российские зоны -> Яндекс DNS напрямую через физический интерфейс (`direct`).
  - ИИ-сервисы и заблокированные зоны -> Self-hosted DoH через VLESS-Reality.
  - Рекламные сети -> `rcode://refused` (мгновенный сброс без нагрузки на сеть).
- Автоматическую загрузку и обновление скомпилированных бинарных `.srs` правил.

```json
{
  "log": {
    "disabled": false,
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "address": "https://dns.example.com/dns-query",
        "address_resolver": "dns-direct",
        "address_strategy": "prefer_ipv4",
        "strategy": "prefer_ipv4",
        "detour": "proxy-out"
      },
      {
        "tag": "dns-direct",
        "address": "https://77.88.8.8/dns-query",
        "address_resolver": "dns-local",
        "address_strategy": "prefer_ipv4",
        "strategy": "prefer_ipv4",
        "detour": "direct"
      },
      {
        "tag": "dns-local",
        "address": "local",
        "detour": "direct"
      },
      {
        "tag": "dns-block",
        "address": "rcode://refused"
      },
      {
        "tag": "dns-fakeip",
        "address": "fakeip"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "dns-direct"
      },
      {
        "rule_set": "geosite-category-ads-all",
        "server": "dns-block",
        "disable_cache": true
      },
      {
        "rule_set": "geosite-ru",
        "server": "dns-direct"
      },
      {
        "domain_suffix": [
          ".ru",
          ".su",
          ".рф",
          ".xn--p1ai",
          "gosuslugi.ru",
          "sberbank.ru",
          "tbank.ru",
          "yandex.net",
          "ya.ru",
          "vk.com"
        ],
        "server": "dns-direct"
      },
      {
        "rule_set": [
          "geosite-openai",
          "geosite-anthropic",
          "geosite-google",
          "geosite-youtube",
          "geosite-instagram",
          "geosite-twitter"
        ],
        "server": "dns-fakeip"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "server": "dns-fakeip"
      }
    ],
    "final": "dns-remote",
    "independent_cache": true,
    "reverse_mapping": true,
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    }
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "sing-box-tun",
      "inet4_address": "172.19.0.1/30",
      "auto_route": true,
      "strict_route": true,
      "stack": "system",
      "sniff": true,
      "sniff_override_destination": true
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy-out",
      "server": "node.example.com",
      "server_port": 443,
      "uuid": "a7b3c4d5-e6f7-48a9-bc01-23456789abcd",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "decoy.example.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "x_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U=",
          "short_id": "0123456789abcdef"
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-ru",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-ru.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-ru",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs",
        "download_detour": "proxy-out"
      },
      {
        "tag": "geosite-anthropic",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-anthropic.srs",
        "download_detour": "proxy-out"
      },
      {
        "tag": "geosite-google",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs",
        "download_detour": "proxy-out"
      },
      {
        "tag": "geosite-youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs",
        "download_detour": "proxy-out"
      },
      {
        "tag": "geosite-instagram",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-instagram.srs",
        "download_detour": "proxy-out"
      },
      {
        "tag": "geosite-twitter",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-twitter.srs",
        "download_detour": "proxy-out"
      }
    ],
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "rule_set": "geosite-category-ads-all",
        "outbound": "block"
      },
      {
        "rule_set": "geosite-ru",
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-ru",
        "outbound": "direct"
      },
      {
        "rule_set": [
          "geosite-openai",
          "geosite-anthropic",
          "geosite-google",
          "geosite-youtube",
          "geosite-instagram",
          "geosite-twitter"
        ],
        "outbound": "proxy-out"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "final": "proxy-out",
    "auto_detect_interface": true
  }
}
```

---

## 5. Архитектура DNS в Amnezia / AmneziaWG и организация Split-DNS

### 5.1. Фундаментальные ограничения протокола WireGuard

Протоколы WireGuard и его обфусцированная модификация AmneziaWG функционируют на **3-м уровне модели OSI (Сетевой уровень / Layer 3)**.
В официальной спецификации WireGuard синтаксис директивы `DNS` в блоке `[Interface]` строго ограничен IP-адресами:
```ini
[Interface]
PrivateKey = aAAA...
Address = 10.8.0.2/24
DNS = 10.8.0.1
```

**Ограничения:**
1. Невозможно указать URL защищенного протокола (DoH, DoT, DoQ).
2. Клиентский драйвер операционной системы (Wintun на Windows, utun на macOS) перехватывает все пакеты на порт 53 UDP и направляет их по указанному IP.
3. Отсутствует встроенный механизм разрешения по доменным маскам внутри самого туннеля (WireGuard оперирует исключительно IP-префиксами `AllowedIPs`).

---

### 5.2. Решение A: Серверный защищенный рекурсивный резолвер

В данной модели на ноде `vpn-installer` поднимается экземпляр AdGuard Home или Unbound, слушающий внутренний адрес туннельного шлюза (например, `10.8.0.1:53` или `172.29.172.1:53`).

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   РЕШЕНИЕ А: СЕРВЕРНЫЙ РЕЗОЛВЕР ДЛЯ AMNEZIAWG                          │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Запрос UDP 53 от клиента (внутри AWG)
                                            ▼
                           ┌──────────────────────────────────┐
                           │    AmneziaWG Server Interface    │
                           │          10.8.0.1:53             │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │      AdGuard Home / Unbound      │
                           │   (Stripping ECS, No Logging)    │
                           └────────────────┬─────────────────┘
                                            │
                 ┌──────────────────────────┴──────────────────────────┐
                 │ (*.ru domains)                                      │ (Foreign / Blocked)
                 ▼                                                     ▼
     ┌───────────────────────┐                             ┌───────────────────────┐
     │ Domestic DNS (Direct) │                             │ Cloudflare DoT (Egress│
     │ 77.88.8.8:53          │                             │ tls://1.1.1.1:853     │
     └───────────────────────┘                             └───────────────────────┘
```

#### Механизм защиты:
1. Запрос UDP 53 от клиента шифруется алгоритмом ChaCha20-Poly1305 внутри пакетов AmneziaWG (с добавлением мусорных байт `Jc`, `Jmin`, `Jmax` и рандомизированных заголовков `H1`–`H4`).
2. Сенсоры ТСПУ видят неразборчивый UDP-поток на нестандартный порт сервера. Спуфинг или перехват UDP 53 физически невозможен.
3. Сервер принимает запрос на `10.8.0.1:53`, выполняет Split-DNS (RU-домены через российские DNS, остальные через локальный Unbound или Cloudflare DoT) и возвращает ответ клиенту через зашифрованный туннель.

---

### 5.3. Решение B: Маршрутизация Split-DNS на уровне роутеров (Keenetic и OpenWrt)

При установке туннеля на домашнем роутере организация Split-DNS переносится на сетевую ОС маршрутизатора.

#### Решение для KeeneticOS:
В роутерах Keenetic реализована встроенная поддержка DNS-профилей (DoH/DoT) и привязки доменных списков:
1. Создается профиль `Encrypted-DNS` с адресами `https://dns.cloudflare.com/dns-query` или адресом собственной ноды.
2. Профиль `Encrypted-DNS` привязывается к интерфейсу туннеля `AmneziaWG0`.
3. В CLI Keenetic настраивается селективное перенаправление:
   ```text
   dns-override domain youtube.com profile Encrypted-DNS
   dns-override domain googlevideo.com profile Encrypted-DNS
   dns-override domain instagram.com profile Encrypted-DNS
   dns-override domain openai.com profile Encrypted-DNS
   ```
4. Для остальных доменов по умолчанию используется системный DNS провайдера, привязанный к основному интерфейсу `ISP`.

#### Решение для OpenWrt (dnsmasq + ipset / nftables + https-dns-proxy):
В среде OpenWrt 22.03 / 23.05 связка `dnsmasq` и `nftables` реализует динамическую маршрутизацию:
1. Устанавливается легковесный клиент DoH:
   ```sh
   opkg update && opkg install https-dns-proxy
   ```
2. В `/etc/config/dhcp` для `dnsmasq` настраиваются условные серверы и динамическое наполнение сетов:
   ```text
   # Направление заблокированных доменов на локальный DoH прокси (127.0.0.1:5053)
   # и автоматическое добавление IP в ipset/nftables vpn_domains
   server=/instagram.com/127.0.0.1#5053
   ipset=/instagram.com/vpn_domains
   server=/youtube.com/127.0.0.1#5053
   ipset=/youtube.com/vpn_domains
   server=/googlevideo.com/127.0.0.1#5053
   ipset=/googlevideo.com/vpn_domains
   server=/openai.com/127.0.0.1#5053
   ipset=/openai.com/vpn_domains
   ```
3. Селектор `nftables` направляет трафик пакетов с адресами из сета `vpn_domains` в интерфейс туннеля `awg0`:
   ```text
   nft add rule inet fw4 prerouting ip daddr @vpn_domains meta mark set 0x100
   ip rule add fwmark 0x100 table 100
   ip route add default dev awg0 table 100
   ```

---

### 5.4. Решение C: Раздельное туннелирование в клиенте AmneziaVPN

Официальное приложение AmneziaVPN реализует разделение трафика на клиентском устройстве (Split Tunneling):
1. **Режим сайтов (Site-based Split Tunneling):** Пользователь загружает список доменов или IP-диапазонов.
   - На Windows приложение использует драйвер WFP (Windows Filtering Platform) и собственный модуль перехвата DNS (`AmneziaDnsService`).
   - Запросы к доменам из списка перехватываются на уровне драйвера сокетов и перенаправляются на DNS-сервер внутри туннеля AmneziaWG (`10.8.0.1:53`).
   - Запросы к остальным доменам передаются стандартному системному сетевому стеку Windows, который опрашивает DNS домашнего маршрутизатора или оператора связи.
2. **Предотвращение утечек Windows Smart Multi-Homed Name Resolution:**
   Windows 10/11 по умолчанию отправляет параллельные DNS-запросы на **все** доступные физические и виртуальные интерфейсы (для ускорения ответа). AmneziaVPN принудительно отключает данный механизм через реестр:
   ```text
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
   ```

---

## 6. Защита от цензуры и приватность в РФ (Противодействие ТСПУ)

### 6.1. Анализ механизмов атак ТСПУ и методы противодействия

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                ВЕКТОРЫ АТАК ТСПУ И МЕРЫ ЗАЩИТЫ                                  │
├───────────────────────────────┬────────────────────────────────┬────────────────────────────────┤
│ Метод воздействия ТСПУ        │ Физика процесса                │ Инженерное решение             │
├───────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **DNS Response Injection**    │ Отправка поддельного пакета с  │ Полный отказ от открытого      │
│ (Спуфинг UDP 53)              │ флагом QR=1 и IP-заглушкой     │ UDP 53. Использование DoH /    │
│                               │ раньше реального ответа.       │ DoH3 на порту 443 TCP/UDP.     │
├───────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **Transparent Redirection**   │ Подмена destination IP пакета   │ Шифрование тела запроса внутри │
│ (Перехват UDP 53)             │ 8.8.8.8 на IP операторского    │ TLS-туннеля до внешнего        │
│                               │ цензурирующего резолвера.      │ собственного сервера.          │
├───────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **DoT Port 853 Drop / RST**   │ Блокировка SYN или инъекция    │ Отказ от порта 853 на WAN.     │
│                               │ TCP RST пакета по номеру порта.│ Перенос резолвера на порт 443  │
│                               │                                │ под маскировку веб-трафика.    │
├───────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **SNI Filtering на DoH**      │ Сброс соединения при чтении    │ Использование собственного     │
│ (Блокировка dns.google и т.д.)│ запрещенного SNI в открытом    │ домена ноды, не входящего      │
│                               │ TLS ClientHello.               │ ни в какие реестры и списки.   │
├───────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ **EDNS Client Subnet Leak**   │ Передача подсети клиента       │ Отключение ECS (`edns_client_  │
│                               │ зарубежному авторитетному DNS. │ subnet: false`) в AdGuard/     │
│                               │ Итог: Бан от OpenAI/Claude.    │ Unbound / Sing-box.            │
└───────────────────────────────┴────────────────────────────────┴────────────────────────────────┘
```

---

### 6.2. Искоренение утечек через EDNS0 Client Subnet (ECS)

Спецификация RFC 7871 (Client Subnet in DNS Queries) была создана для оптимизации доставки контента глобальными CDN: резолвер передает авторитетному серверу префикс IP-адреса клиента (например, `/24`), чтобы CDN выдал IP ближайшего локального сервера.

#### Опасность ECS в условиях обхода блокировок:
1. Если клиент обращается к DoH через зарубежный прокси, но DoH-сервер включает ECS с исходным IP клиента из РФ, зарубежные сервисы (OpenAI, Claude, Anthropic) мгновенно определяют геолокацию запроса как «Российская Федерация» и возвращают HTTP 403 Forbidden или ошибку доступа.
2. Цензоры и аналитические системы при перехвате трафика на авторитетных серверах могут сопоставлять запросы с конкретными подсетями абонентов.

#### Меры конфигурации:
- В **AdGuard Home**:
  ```yaml
  dns:
    edns_client_subnet:
      enabled: false
  ```
- В **Sing-box**:
  ```json
  {
    "dns": {
      "servers": [
        {
          "tag": "dns-remote",
          "address": "https://dns.example.com/dns-query",
          "client_subnet": "0.0.0.0/0"
        }
      ]
    }
  }
```
- В **Unbound**:
  ```text
  server:
      send-client-subnet: no
  ```

---

### 6.3. Защита метаданных: QNAME Minimization (RFC 9156)

В классическом DNS резолвер отправляет полное запрашиваемое доменное имя на каждом шаге рекурсии:
- Запрос к Корневому серверу (`.`): `Каков адрес api.openai.com?`
- Запрос к серверу зоны `.com`: `Каков адрес api.openai.com?`
- Запрос к авторитетному серверу `openai.com`: `Каков адрес api.openai.com?`

При включенном механизме **QNAME Minimization**:
- Запрос к Корневому серверу (`.`): `Каковы серверы зоны com?` (сервер не узнает о существовании openai).
- Запрос к серверу зоны `.com`: `Каковы серверы зоны openai.com?`
- Запрос к авторитетному серверу `openai.com`: `Каков адрес api.openai.com?`

Это полностью исключает сбор истории веб-серфинга на промежуточных корневых и региональных серверах имен.

---

## 7. Сравнительная матрица решений и инженерные рекомендации

### 7.1. Сравнительная матрица архитектурных подходов

| Параметр | Sing-box Built-in DNS | AdGuard Home (DoH/DoT) | Unbound + CoreDNS | AmneziaWG Server-Side |
|---|---|---|---|---|
| **Поддерживаемые протоколы** | UDP, TCP, DoH, DoT, DoH3, FakeIP | UDP, TCP, DoH, DoT, DoQ, DoH3 | UDP, TCP, DoT, Unbound Recurse | UDP 53 (внутри туннеля) |
| **Точность Split-DNS** | **Идеальная** (Rule-sets `.srs`, geosite) | Средняя (доменные маски `[/domain/]`) | Высокая (плагины CoreDNS) | Зависит от апстрима на сервере |
| **Накладные расходы (RAM)** | **Минимальные** (~10–25 МБ) | Средние (~40–90 МБ) | Умеренные (~30–70 МБ) | ~40 МБ (AdGuard на шлюзе) |
| **Задержка ответа** | 0 мс (FakeIP) / RTT до прокси | 1–5 мс (Кэш) / RTT до апстрима | 1 мс (Кэш) / 80–200 мс (Итерация)| RTT туннеля + 1 мс |
| **Стойкость к ТСПУ** | **Максимальная** (инкапсуляция) | **Максимальная** (DoH за Caddy) | Средняя (прямые запросы к корням)| **Максимальная** (AWG обфускация)|
| **Фильтрация рекламы** | Да (через `geosite-category-ads`) | **Превосходная** (AdGuard/OISD базы)| Нет (требует списков CoreDNS) | Превосходная (если AdGuard) |
| **Сложность развертывания**| Минимальная (единый бинарник) | Низкая (Docker Compose) | Средняя (конфигурация связки) | Низкая (часть развертывания ноды)|

---

### 7.2. Итоговые инженерные рекомендации

1. **Для клиентских устройств с поддержкой Sing-box (Android, Windows, macOS, Linux, iOS):**
   - **Выбор стека:** Использовать клиентский движок **Sing-box с архитектурой Inbound TUN и FakeIP**.
   - **Конфигурация апстримов:**
     - Российские домены (`geosite-ru`, `.ru`, `.рф`, банки) направлять напрямую на `https://77.88.8.8/dns-query` через outbound `direct`.
     - Заблокированные домены, соцсети и ИИ-платформы направлять через FakeIP на outbound `proxy-out` (VLESS-Reality / ShadowTLS).
     - Рекламные сети отсекать правилом `dns-block` (`rcode://refused`).
   - **Результат:** Нулевой пинг при открытии сайтов, полное отсутствие утечек DNS, 100% доступность сервисов обеих юрисдикций.

2. **Для устройств под управлением Amnezia / AmneziaWG:**
   - **Выбор стека:** **Решение A (Серверный защищенный рекурсивный резолвер)**.
   - **Конфигурация:**
     - Развернуть контейнер `adguard-home` на ноде `vpn-installer` с привязкой к IP шлюза туннеля (`10.8.0.1:53`).
     - В клиентском конфигурационном файле жестко зафиксировать `[Interface] DNS = 10.8.0.1`.
     - В AdGuard Home настроить условный форвардинг российских доменов на Яндекс DNS, а остальных доменов — на Cloudflare DoT с принудительно отключенным ECS (`edns_client_subnet: false`).
   - **Результат:** Невозможность перехвата или подмены DNS провайдером клиента, корректное разрешение локальных и международных ресурсов.

3. **Для роутеров Keenetic / OpenWrt:**
   - Использовать **Решение B (Router-level Split-DNS)** с разделением на уровне `dnsmasq`/`Keenetic DNS-профилей`.
   - Направлять только адреса из списков блокировок через туннель AmneziaWG, сохраняя стандартный DNS провайдера для фонового интернет-трафика домашней сети.

4. **Для публичных точек разрешения (Self-Hosted DoH/DoT Endpoint):**
   - Ни в коем случае не публиковать открытый порт 853 или 53 в интернет.
   - Развертывать DoH исключительно на порту **443 TCP/UDP (HTTP/2 + HTTP/3)** за обратным прокси-сервером **Caddy**, прикрытым аутентичным маскировочным сайтом (Decoy Site).
   - Использовать нестандартный URI эндпоинта (например, `/v1/dns-query-protected`) для полной защиты от сигнатурных сканеров сетевой цензуры.

---

## 8. Первичные источники и нормативные документы

### 8.1. Спецификации IETF RFC
- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) — Domain Names - Implementation and Specification (Базовый стандарт DNS).
- [RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033) — DNS Security Introduction and Requirements (DNSSEC Overview).
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — Resource Records for the DNS Security Extensions.
- [RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035) — Protocol Modifications for the DNS Security Extensions.
- [RFC 7816](https://datatracker.ietf.org/doc/html/rfc7816) — DNS Query Name Minimisation to Improve Privacy.
- [RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858) — Specification for DNS over Transport Layer Security (DoT).
- [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871) — Client Subnet in DNS Queries (EDNS0 Client Subnet).
- [RFC 8198](https://datatracker.ietf.org/doc/html/rfc8198) — Aggressively Use of DNSSEC-Validated Cache (NSEC).
- [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) — DNS Queries over HTTPS (DoH).
- [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114) — HTTP/3 (Транспорт для DoH3).
- [RFC 9156](https://datatracker.ietf.org/doc/html/rfc9156) — DNS Query Name Minimisation to Improve Privacy (Актуализированный стандарт).
- [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250) — DNS over Dedicated QUIC Connections (DoQ).

### 8.2. Официальная документация проектов и репозитории
- **Sing-box:**
  - [Sing-box DNS Configuration Specification](https://sing-box.sagernet.org/configuration/dns/)
  - [Sing-box Inbound DNS & TUN Documentation](https://sing-box.sagernet.org/configuration/inbound/tun/)
  - [Sing-box Rule-Set Compilation and SRS Format](https://sing-box.sagernet.org/configuration/route/rule_set/)
- **AdGuard Home:**
  - [AdGuard Home Official Wiki & Configuration Guide](https://github.com/AdguardTeam/AdGuardHome/wiki)
  - [AdGuard Home DNS-over-HTTPS and DNS-over-QUIC Setup](https://github.com/AdguardTeam/AdGuardHome/wiki/Encryption)
- **NLnet Labs Unbound:**
  - [Unbound Documentation & Hardening Guidelines](https://nlnetlabs.nl/documentation/unbound/)
- **CoreDNS:**
  - [CoreDNS Manual & Plugin Documentation](https://coredns.io/manual/toc/)
- **AmneziaWG & WireGuard:**
  - [AmneziaWG Protocol Specification and Repository](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
  - [WireGuard Technical Whitepaper (Jason A. Donenfeld)](https://www.wireguard.com/papers/wireguard.pdf)
- **Базы данных правил маршрутизации:**
  - [SagerNet Sing-Geosite Repository (Binary SRS Rulesets)](https://github.com/SagerNet/sing-geosite)
  - [SagerNet Sing-GeoIP Repository](https://github.com/SagerNet/sing-geoip)
