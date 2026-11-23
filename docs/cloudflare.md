# Cloudflare: вход через аккаунт

niceproxy использует официальный OAuth 2.0 Authorization Code + PKCE (S256). Кнопка «Войти через Cloudflare» открывает сайт Cloudflare в отдельном окне. Войдите, выберите аккаунт и подтвердите права. Окно закроется, а панель niceproxy загрузит доступные зоны. Если браузер блокирует окно, вход откроется в текущей вкладке. Для подключения достаточно зарегистрированного публичного OAuth-клиента.

## Однократная регистрация приложения

Cloudflare требует зарегистрированный OAuth client. В репозитории нет чужого Client ID или универсального идентификатора приложения: для своей установки зарегистрируйте niceproxy в Cloudflare.

Откройте [Cloudflare → Manage Account → OAuth clients](https://dash.cloudflare.com/?to=/:account/oauth-clients), нажмите создание клиента и заполните форму так:

| Поле в Cloudflare | Что указать |
| --- | --- |
| **Client Name** | `niceproxy` или другое понятное имя установки |
| **Response Type** | `Code` |
| **Grant type** | `Authorization Code` |
| **Token Authentication Method** | `None` |
| **Redirect (Callback) URLs** | точный callback из панели niceproxy, одна строка |
| **Client URL** *(optional)* | оставить пустым |
| **Logo** *(optional)* | оставить пустым |
| **Policy URL** *(optional)* | оставить пустым |
| **Terms of Service URL** *(optional)* | оставить пустым |
| **Post-logout Redirect URLs** *(optional)* | оставить пустым |
| **Allowed CORS Origins** *(optional)* | оставить пустым |

niceproxy использует Authorization Code вместе с PKCE S256, поэтому Client Secret не нужен. Отдельно добавлять `refresh_token` в Grant type не нужно: niceproxy запрашивает обновление доступа через scope `offline_access`.

### Как получить непустой Redirect URI

Поле **Redirect URI** в панели niceproxy заполняется автоматически только для loopback-панели. При стандартном запуске используйте:

```text
http://127.0.0.1:9080/api/cloudflare/callback
```

Если панель слушает LAN-адрес, `0.0.0.0` или доменное имя, без явной настройки поле останется пустым. Задайте callback через `NICEPROXY_CF_REDIRECT_URL`, затем перезапустите niceproxy. Для Docker добавьте в `.env`:

```dotenv
NICEPROXY_CF_REDIRECT_URL=https://panel.example.com/api/cloudflare/callback
```

Для адреса, доступного с другой машины, нужен HTTPS. В Cloudflare и в niceproxy значение должно совпадать полностью, включая схему, имя хоста и порт. Не указывайте в Cloudflare `0.0.0.0`, адрес контейнера или URL с query-параметрами. Для запуска на другом локальном порту замените `9080`, например `http://127.0.0.1:19080/api/cloudflare/callback`.

После перезапуска скопируйте значение из поля **Redirect URI** панели кнопкой **Скопировать** и вставьте его в поле **Redirect (Callback) URLs** Cloudflare. Для полностью локального запуска это обычный `http://127.0.0.1:9080/...`, домен не требуется.

Если callback должен использовать отдельный домен или субдомен, в настройках OAuth niceproxy заполните поле **Домен для Cloudflare callback**, например `cf.example.com`. niceproxy сам добавит `https://` и `/api/cloudflare/callback`, сохранит настройку и покажет готовый URL для копирования. Создайте для этого имени DNS-запись и настройте HTTPS reverse proxy на панель niceproxy. После сохранения открывайте niceproxy через этот домен, иначе вход будет отклонён проверкой Host.

Настроенный callback также показывается отдельной карточкой в разделе **Маршруты**. Эта карточка информирует о служебном OAuth-адресе и не добавляет его в конфигурацию Caddy.

Если поле **Redirect URI** по-прежнему пустое, оставьте домен callback заполненным и сохраните настройки. Вариант через переменную окружения также поддерживается.

### Scope ID и сохранение настроек

1. Выберите минимальные права: Zone Read, DNS Read и DNS Write для нужных ресурсов. Для обновления доступа нужен `offline_access`.
2. Cloudflare связывает эти права с OAuth scope ID. В поле **Scope ID** панели niceproxy вставьте именно ID, показанные Cloudflare для зарегистрированного клиента, через пробел или запятую. Не подставляйте названия API token permissions или вымышленные `dns:*`. Доступные ID также возвращает защищённый endpoint `/client/v4/oauth/scopes`.
3. Сохраните публичный Client ID и Scope ID в разделе Cloudflare niceproxy. Это настройки приложения, не секреты аккаунта.
4. Нажмите «Войти через Cloudflare» и подтвердите права на странице Cloudflare.

Private-клиент доступен членам аккаунта, в котором он зарегистрирован. Для распространения единого OAuth-клиента среди пользователей других аккаунтов Cloudflare требует public visibility и проверку домена издателя. Перевод в public не нужен для личной установки.

Подробности: [регистрация OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), [управление выданным доступом](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

После входа доступны домены и DNS-записи разрешённых зон. Можно явно создать A, AAAA или CNAME, либо изменить выбранную запись. Существующие записи не перезаписываются автоматически. Вход в аккаунт и создание маршрута niceproxy сами по себе DNS не меняют.

DNS указывает адрес сервера, а не URL с портом или путём. Cloudflare proxy по умолчанию выключен (DNS only); обычный HTTP proxy Cloudflare не публикует произвольные TCP/UDP-порты. Эта интеграция не создаёт Cloudflare Tunnel и не меняет путь передачи трафика niceproxy. Сертификаты HTTP/HTTPS по-прежнему выпускает Caddy. DNS-01 через Cloudflare в этой версии не подключён.

## Данные и доступ

Access/refresh tokens хранятся в SQLite только в зашифрованном виде (AES-GCM). Ключ `/data/cloudflare.key` имеет права `0600`. В нативном запуске он лежит в каталоге `--data`. Резервируйте БД и этот ключ вместе: потерянный ключ не заменяется новым поверх сохранённого подключения. Токены не возвращаются через API панели и не записываются в журнал.

Начало OAuth требует действующей сессии администратора. Callback проверяет одноразовый state, PKCE и сессию, начавшую подключение. Отключение удаляет локальное подключение и пытается отозвать доступ в Cloudflare; при сетевой ошибке панель предлагает проверить отзыв в Cloudflare вручную.

`NICEPROXY_CF_REDIRECT_URL` задаёт callback по умолчанию; для loopback-панели адрес определяется автоматически. Домен, сохранённый в настройках OAuth панели, имеет приоритет и сохраняется в SQLite вместе с Client ID и scopes. Изменение этих настроек отключает прежнее подключение.

Для работы реального входа нужны зарегистрированный client и разрешённые scopes. Без них панель показывает подготовку интеграции, а не имитирует успешное подключение. Протокол, refresh и DNS-клиент проверяются локальными тестовыми OAuth/API-серверами; реальный аккаунт подключается пользователем.
