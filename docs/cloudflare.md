# Cloudflare: вход через аккаунт

niceproxy использует официальный OAuth 2.0 Authorization Code + PKCE (S256). Кнопка «Войти через Cloudflare» открывает сайт Cloudflare в отдельном окне. Войдите, выберите аккаунт и подтвердите права. Окно закроется, а панель niceproxy загрузит доступные зоны. Если браузер блокирует окно, вход откроется в текущей вкладке. Для подключения достаточно зарегистрированного публичного OAuth-клиента.

## Однократная регистрация приложения

Cloudflare требует зарегистрированный OAuth client. В репозитории нет чужого Client ID или универсального идентификатора приложения: для своей установки зарегистрируйте niceproxy в Cloudflare.

1. В [Cloudflare → Manage Account → OAuth clients](https://dash.cloudflare.com/?to=/:account/oauth-clients) создайте клиент niceproxy.
2. Response type: `code`. Grant types: `authorization_code` и `refresh_token`. Token endpoint authentication method: `none` (PKCE).
3. Redirect URL скопируйте из раздела Cloudflare панели niceproxy. Для текущего локального запуска это `http://127.0.0.1:19080/api/cloudflare/callback`; для Docker по умолчанию — `http://127.0.0.1:9080/api/cloudflare/callback`. Адрес должен точно совпадать, включая порт. HTTP разрешён только на loopback; для удалённого адреса нужен HTTPS.
4. Выберите минимальные права: Zone Read, DNS Read и DNS Write для нужных ресурсов. Для обновления доступа нужен `offline_access`. Cloudflare связывает эти права с OAuth scope ID; используйте ID, показанные для зарегистрированного клиента. Не подставляйте названия API token permissions или вымышленные `dns:*`. Доступные ID также возвращает защищённый endpoint `/client/v4/oauth/scopes`.
5. Сохраните публичный Client ID и scope ID в разделе Cloudflare niceproxy. Это настройки приложения, не секреты аккаунта.
6. Нажмите «Войти через Cloudflare» и подтвердите права на странице Cloudflare.

Private-клиент доступен членам аккаунта, в котором он зарегистрирован. Для распространения единого OAuth-клиента среди пользователей других аккаунтов Cloudflare требует public visibility и проверку домена издателя. Перевод в public не нужен для личной установки.

Подробности: [регистрация OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), [управление выданным доступом](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

После входа доступны домены и DNS-записи разрешённых зон. Можно явно создать A, AAAA или CNAME, либо изменить выбранную запись. Существующие записи не перезаписываются автоматически. Вход в аккаунт и создание маршрута niceproxy сами по себе DNS не меняют.

DNS указывает адрес сервера, а не URL с портом или путём. Cloudflare proxy по умолчанию выключен (DNS only); обычный HTTP proxy Cloudflare не публикует произвольные TCP/UDP-порты. Эта интеграция не создаёт Cloudflare Tunnel и не меняет путь передачи трафика niceproxy. Сертификаты HTTP/HTTPS по-прежнему выпускает Caddy. DNS-01 через Cloudflare в этой версии не подключён.

## Данные и доступ

Access/refresh tokens хранятся в SQLite только в зашифрованном виде (AES-GCM). Ключ `/data/cloudflare.key` имеет права `0600`. В нативном запуске он лежит в каталоге `--data`. Резервируйте БД и этот ключ вместе: потерянный ключ не заменяется новым поверх сохранённого подключения. Токены не возвращаются через API панели и не записываются в журнал.

Начало OAuth требует действующей сессии администратора. Callback проверяет одноразовый state, PKCE и сессию, начавшую подключение. Отключение удаляет локальное подключение и пытается отозвать доступ в Cloudflare; при сетевой ошибке панель предлагает проверить отзыв в Cloudflare вручную.

`NICEPROXY_CF_REDIRECT_URL` задаёт зарегистрированный callback URL; для loopback-панели адрес определяется автоматически. Client ID/scopes сохраняются отдельно от токенов. Изменение этих настроек отключает прежнее подключение.

Для работы реального входа нужны зарегистрированный client и разрешённые scopes. Без них панель показывает подготовку интеграции, а не имитирует успешное подключение. Протокол, refresh и DNS-клиент проверяются локальными тестовыми OAuth/API-серверами; реальный аккаунт подключается пользователем.
