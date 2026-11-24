# CGP Certificate Manager

Автоматическое управление сертификатами Let's Encrypt для многодоменного почтового сервера CommuniGate Pro. Использует Certbot, Cloudflare DNS-01 и локальный HTTP CLI CommuniGate.

[English documentation](README.md)

## Возможности

- Обнаружение доменов и псевдонимов, исключение IP-адресов, поддержка IDN, wildcard и SAN.
- Проверка доступности зон Cloudflare и DNS-делегирования; защита от сокращения SAN при потере доступа к зоне.
- Автоматическое продление и установка сертификатов без запроса перезапуска CGServer.
- Полная цепочка CA в формате объединённых DER-сертификатов, активация PKI через CertificateType=YES.
- Проверка соответствия ключа, чтение параметров после записи, проверка TLS, SNI, имени и отпечатков полной цепочки.
- Резервные копии, восстановление при ошибке установки, раздельный backoff, история и SMTP-уведомления.
- Плановое обслуживание через systemd.

## Установка

Проверенная среда: Ubuntu 24.04 LTS. Необходим локальный HTTP CLI CommuniGate с правами чтения и изменения настроек обслуживаемых доменов. API-токен Cloudflare должен иметь права Zone Read и DNS Edit для соответствующих зон.

    sudo apt update
    sudo apt install certbot python3-certbot-dns-cloudflare python3 openssl ca-certificates dnsutils iproute2
    git clone https://github.com/alphazulu/cgp-certificate-manager.git
    cd cgp-certificate-manager

Для новой установки создайте конфигурацию:

    sudo install -d -m 700 /etc/cgp-letsencrypt
    sudo install -m 600 examples/config.example.json /etc/cgp-letsencrypt/config.json
    sudo install -m 600 examples/cloudflare.example.ini /etc/cgp-letsencrypt/cloudflare.ini
    sudoedit /etc/cgp-letsencrypt/config.json
    sudoedit /etc/cgp-letsencrypt/cloudflare.ini
    sudo bash install.sh

При обновлении не перезаписывайте действующую конфигурацию примерами. Установщик сохраняет резервную копию прежней версии и оставляет таймер остановленным. Certbot-сертификаты сохраняются.

CLI должен быть доступен через loopback, например http://127.0.0.1:8100/CLI/. По умолчанию проверяется HTTPS на порту 443. При необходимости задайте tls (host, port, sni, starttls). Параметры domains позволяют задать enabled, wildcard, extra_names, exclude_names, cert_name и tls. Для нескольких аккаунтов Cloudflare используйте cloudflare_accounts с путями credentials. Для SMTP-уведомлений настройте notifications.

Если у домена ещё нет всех четырёх читаемых параметров сертификата, автоматическая установка блокируется: сначала подготовьте исправный сертификат через WebAdmin. Это ограничение механизма резервного копирования.

## Проверка и запуск

    sudo cgp-letsencrypt --sync
    sudo cgp-letsencrypt --doctor
    sudo cgp-letsencrypt --plan
    sudo cgp-letsencrypt --domain example.com --dry-run
    sudo cgp-letsencrypt --domain example.com
    sudo cgp-letsencrypt --verify
    sudo systemctl start cgp-letsencrypt.service
    sudo systemctl enable --now cgp-letsencrypt.timer

Замените example.com на свой домен. Отключайте certbot.timer только если все его сертификаты обслуживаются менеджером.

## Команды

| Команда | Назначение |
|---|---|
| --sync, --list, --show-domains | Домены и псевдонимы |
| --doctor, --status, --plan | Диагностика и план |
| --verify | Проверка TLS и цепочек |
| --discover-listeners, --verify-listeners | Диагностика слушателей |
| --dry-run | Тестовый выпуск |
| --install-only, --repair-chain | Установка без выпуска |
| --retry-now | Игнорировать backoff |
| --domain DOMAIN --reset-backoff | Сбросить backoff |
| --backups DOMAIN, --rollback DOMAIN | Резервные копии и восстановление |
| --history, --json, --version | История, JSON, версия |
| --allow-shrink, --force-renew | Явное разрешение сокращения SAN, принудительное продление |

## Безопасность и ограничения

Конфигурация находится в /etc/cgp-letsencrypt, состояние и резервные копии в /var/lib/cgp-letsencrypt, сертификаты Certbot в /etc/letsencrypt. Не публикуйте пароли, токены и приватные ключи. Резервные копии должны быть доступны только root. Rollback выполняется через API и не является атомарной транзакцией CGP. Проверка DNSSEC и CAA в полном объёме не реализована. Не все TLS-слушатели поддерживают SNI.

    journalctl -u cgp-letsencrypt.service -n 100 --no-pager
    python3 -m unittest discover -s tests -v

Версия 2.0.1 проверена на действующем многодоменном сервере. Модульные тесты не заменяют проверку конкретной инсталляции. Независимый проект; лицензия пока не выбрана.

## Опциональный TUI (разработка 2.1)

Установите whiptail командой sudo apt install whiptail. Запустите sudo bash install.sh --tui для интерактивной настройки или sudo bash install.sh --non-interactive с готовой конфигурацией. При обновлении по умолчанию сохраняются настройки. Для изменения настроек после установки используйте sudo cgp-letsencrypt --tui. Мастер позволяет настроить CGP, несколько токенов Cloudflare, домены, wildcard и SAN, email ACME, задержку DNS, TLS и SMTP. Новые установки по умолчанию требуют выбора доменов. Сохранение не выпускает сертификаты и не включает таймер. Проверка прав DNS Edit выполняется отдельно через dry-run. Главное меню и основные запросы доступны на русском и английском, часть диагностических сообщений пока на английском. Можно настроить TLS отдельного домена и расписание. После изменения расписания в установленной системе выполните sudo cgp-letsencrypt --apply-schedule. Команда применяет drop-in systemd, но не включает остановленный таймер. Установщик применяет расписание автоматически.

### Выход из мастера настройки

Первые два пункта меню — «Сохранить и выйти» и «Выйти без сохранения». Кнопка «Выход» и Escape в главном меню запрашивают подтверждение при наличии изменений. Во вложенных меню кнопка «Назад». Ctrl+C прерывает работу. Отмена интерактивной установки прекращает её до копирования приложения и systemd units. Самостоятельный настройщик возвращает код 3 при отмене и 0 при сохранении.
