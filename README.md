# Keenetic Policy UI
[![GitHub Release](https://img.shields.io/github/v/release/JohnDoe150489/keenetic-policy-ui)](https://github.com/JohnDoe150489/keenetic-policy-ui/releases)

Веб-интерфейс для управления политиками доступа на роутерах Keenetic/Netcraze с Entware (OPKG). Позволяет назначать каждому устройству свою политику, переключать DNS-профили вместе с политиками и управлять всем из браузера — без необходимости заходить в веб-интерфейс роутера.
По умолчанию без авторизации на роутере клиенты видят и могут переключать политику только своего устройства (есть и режим без логина).
<p align="center">
  <img src="https://github.com/JohnDoe150489/keenetic-policy-ui/blob/main/.github/screenshot.png" alt="Keenetic Policy UI screenshot">
    <img src="https://github.com/JohnDoe150489/keenetic-policy-ui/blob/main/.github/screenshot_2.png" alt="Keenetic Policy UI policy settings screenshot">
</p>

---

**Содержание:**
- [Особенности](#особенности)
- [Подготовка Keenetic](#подготовка-keenetic)
- [Установка](#установка)
- [Настройка](#настройка)
- [API](#api)
- [Безопасность](#безопасность)
- [Обновление](#обновление)
- [Удаление](#удаление)
- [Сборка из исходников](#сборка-из-исходников)
- [Благодарности](#благодарности)

---

## Особенности

- **Настройка политик из интерфейса** — добавляйте, редактируйте и удаляйте кнопки политик прямо в веб-UI. Выбирайте имя политики из списка созданных на роутере, назначайте надпись (или эмодзи) на кнопку, цвет и описание.
- **Переключение политик своего устройства без входа на роутер** — по умолчанию без логина на роутере клиенты видят и могут переключать политику только своего устройства.
- **Режим без авторизации** — возможно отключить аутентификацию в конфиге. Пользователи смогут менять политики чужих устройств.
- **Привязка DNS-профилей** — каждой политике можно сопоставить DNS-профиль роутера. При переключении политики DNS профиль меняется автоматически. Если политике не назначен DNS-профиль, то при её применении DNS профиль устройства сбрасывается на значение по умолчанию для сегмента сети.
- **Низкое потребление ресурсов** — PHP-CGI запускается по запросу, lighttpd потребляет ~4-5 MB RAM, возможна установка во внутреннюю память роутера.
- **Работа через RCI** — API общается с роутером через штатный RCI (`127.0.0.1:79`).
- **Аутентификация через роутер** — используется challenge-response механизм Keenetic (X-NDM). Пароль не передаётся в открытом виде.
- **API для автоматизации** — REST API для интеграции с умным домом, скриптами и Home Assistant.
- **X-Token для внешних устройств** — статический API-токен для переключения политик с других устройств без логина.

## Подготовка Keenetic

Для работы необходима система пакетов Entware. Установите её:
- [на USB-накопитель](https://support.keenetic.ru/ultra/kn-1811/ru/20980-installing-the-entware-repository-on-a-usb-drive.html)
- [во внутреннюю память](https://support.keenetic.ru/ultra/kn-1811/ru/18482-installing-opkg-entware-in-the-router-s-internal-memory.html)

Подключитесь по SSH:

```bash
ssh root@192.168.1.1 -p 222
```

Пароль по умолчанию: `keenetic`

Все необходимые зависимости (lighttpd, php8-cgi, php8-mod-curl, модули lighttpd) устанавливаются автоматически при установке пакета.

---
## Установка

### Установка на Keenetic/Netcraze через репозиторий (рекомендуется)

1. Установите необходимые зависимости
   ```bash
   opkg update
   opkg install ca-certificates wget-ssl
   ```

2. Установите opkg-репозиторий в систему
   ```bash
   mkdir -p /opt/etc/opkg
   echo "src/gz keenetic_policy_ui https://johndoe150489.github.io/keenetic-policy-ui" > /opt/etc/opkg/keenetic-policy-ui.conf
   ```

3. Установите пакет
   ```bash
   opkg update
   opkg install keenetic-policy-ui
   ```
После установки интерфейс будет доступен по адресу: **http://&lt;роутер&gt;:3000/**

##### Обновление

```bash
opkg update
opkg upgrade keenetic-policy-ui
```
---

### Ручная установка из файла

Скачайте [последний релиз](https://github.com/JohnDoe150489/keenetic-policy-ui/releases) и установите вручную:

```bash
wget https://github.com/JohnDoe150489/keenetic-policy-ui/releases/download/v1.0.0/keenetic-policy-ui_1.0.0_all_entware.ipk
opkg install keenetic-policy-ui_1.0.0_all_entware.ipk
```

### Настройка политик

Через веб-интерфейс выполните вход на роутер кнопкой Login, нажмите кнопку настройки (⚙):
1. Выберите имя политики из списка созданных на роутере
2. Задайте кнопку-символ (эмодзи или текст до 8 символов)
3. Выберите цвет для кнопки
4. Добавьте описание
5. При необходимости привяжите DNS-профиль роутера

Первая строка — это всегда политика по умолчанию **"Default"**. У неё `id=""`, она не редактируется и не удаляется.
Если политика у устройства не переключается, зарегистрируйте его в веб-интерфейсе Keenetic в меню управления устройствами.

---

## Настройка

### Файл конфигурации

Конфигурация находится в `/opt/etc/keenetic-policy-ui/keenetic-policy-ui.conf`:

```ini
[router]
; RCI API — не изменяйте, локальный RCI роутера
rci_url = http://127.0.0.1:79

[auth]
; Требовать логин для управления чужими устройствами
enabled = true
; Секрет для JWT — оставьте пустым для автогенерации
jwt_secret =
; Статический API-токен для внешних скриптов
api_token =

[app]
; Файл с настройками политик
policies_file = /opt/etc/keenetic-policy-ui/policies.json
; Уровень лога: silent, error, warn, info, debug
log_level = info
; Файл для лога — оставьте пустым, и лог будет только в syslog
log_file =
```

### Режим без логина

Установите `enabled = false` в секции `[auth]`:

```ini
[auth]
enabled = false
```

В этом режиме любой, кто имеет доступ к порту 3000 (в вашей сети), может менять политики всех устройств.

---

## API

#### `POST /api/devices/{mac}/policy`

Установить политику Policy1 для устройства по MAC-адресу (для режима без авторизации):

```bash
curl -X POST http://192.168.1.1:3000/api/devices/aa:bb:cc:dd:ee:ff/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"Policy1"}'
```

```json
// Response
{ "success": true, "verified": true, "policy": "Policy0", "policyLabel": "VPN" }
```

Передайте `"policy": ""` чтобы сбросить на Default.

#### `POST /api/policy`

Установить политику Policy1 для своего устройства (MAC определяется по IP-адресу):

```bash
curl -X POST http://192.168.1.1:3000/api/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"Policy1"}'
```

### X-Token для быстрого переключения (в режиме с авторизацией)

Настройте статический API-токен в конфиге:

```ini
[auth]
api_token = my-secret-token-123
```

Используйте его в заголовке `X-API-Token`:

```bash
# Переключить устройство на политику Policy1 (в режиме с авторизацией)
curl -X POST http://192.168.1.1:3000/api/devices/aa:bb:cc:dd:ee:ff/policy \
  -H "X-API-Token: my-secret-token-123" \
  -H "Content-Type: application/json" \
  -d '{"policy":"Policy1"}'
```

### Пример для Home Assistant

```yaml
rest_command:
  keenetic_vpn_on:
    url: "http://192.168.1.1:3000/api/devices/aa:bb:cc:dd:ee:ff/policy"
    method: POST
    headers:
      Content-Type: application/json
      X-API-Token: "my-secret-token-123"
    payload: '{"policy": "Policy1"}'

  keenetic_vpn_off:
    url: "http://192.168.1.1:3000/api/devices/aa:bb:cc:dd:ee:ff/policy"
    method: POST
    headers:
      Content-Type: application/json
      X-API-Token: "my-secret-token-123"
    payload: '{"policy": ""}'
```

---

## Безопасность

- **Пароль роутера** — не передаётся в открытом виде, хеш считается на стороне браузера (MD5 + SHA256 challenge-response)
- **JWT** — подписывается секретом, сгенерированным на роутере. 24 часа жизни
- **RCI** — работает только на localhost (`127.0.0.1:79`)
- **API-токен** — хранится в конфиге, доступном только root

**Важно:** интерфейс не предназначен для публикации в интернет без HTTPS и авторизации. Не делайте проброс порта 3000 во внешнюю сеть. Используйте его только внутри домашней сети или через VPN.

---

## Обновление

```bash
opkg update
opkg upgrade keenetic-policy-ui
```

После обновления перезапустите lighttpd:

```bash
/opt/etc/init.d/S80lighttpd restart
```

## Удаление

```bash
opkg remove keenetic-policy-ui
```

Если нужно удалить и файлы конфигурации:

```bash
rm -rf /opt/etc/keenetic-policy-ui
rm -rf /opt/share/www/keenetic-policy-ui
rm -f /opt/etc/lighttpd/conf.d/80-keenetic-policy-ui.conf
```

## Сборка из исходников

```bash
git clone https://github.com/JohnDoe150489/keenetic-policy-ui.git
cd keenetic-policy-ui
make
```

Готовый .ipk появится в директории `out/`.

## Благодарности

Идея и интерфейс проекта основана на [keenetic-vpn-ui](https://github.com/Wain-PC/keenetic-vpn-ui) от Wain-PC. Спасибо за вдохновение.

---

**GitHub:** [https://github.com/JohnDoe150489/keenetic-policy-ui](https://github.com/JohnDoe150489/keenetic-policy-ui)
