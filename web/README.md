# Niceproxy web

Веб-панель Niceproxy на React + TypeScript и Alpha UI 0.4.12-niceproxy.4 (локальное расширение из исходников 0.4.11). Интерфейс на русском: первичная настройка и вход по паролю, CRUD HTTP/HTTPS маршрутов и TCP/UDP правил, состояние сохранённой и применённой ревизий.

Структура экранов и иерархия акцентов: [дизайн интерфейса](../docs/ui-design.md).

```sh
cd web
npm ci
npm run typecheck
npm run build
npm start
```

`npm start` запускает `scripts/alpha-bootstrap.mjs`. При `NICEPROXY_ALPHA_RELEASE_URL` скрипт проверяет `latest.json`, manifest и SHA-512 архивов core/react/project-server, собирает staging в пределах общего таймаута 20 секунд и активирует только готовую сборку. Без URL явно используется локальная версия; ошибки и таймауты откатываются к последней рабочей сборке. `node scripts/alpha-bootstrap.mjs --prepare` печатает путь активной сборки без запуска сервера.

API: `GET /api/auth`; `POST /api/setup` и `/api/login` `{password}`; `POST /api/logout`; `GET /api/config` `{revision,panelDomain,httpRoutes,directRules}`; `GET/PATCH /api/panel-domain`; CRUD `/api/http-routes/:id` и `/api/direct-rules/:id`; `GET /api/health` `{status,state,caddy,revision,appliedRevision,panelDomain,certificate,error?}`. Non-2xx ответы содержат JSON `error`, а 401 возвращает экран входа. UI builds are selected from `/data/ui` only after atomic marker, version and digest validation.
