# Alpha's UI

Архивы пакетов и их контрольные суммы перечислены в `manifest.json`.
Соответствующие [исходники этого выпуска](alpha-ui-source-0.4.12-niceproxy.3.tar.gz), их размер и SHA-512 указаны в `manifest.source`.
В архиве сохранены канонические компоненты, runtime, сборочные скрипты, package-lock.json и лицензии.
После распаковки выполни `npm ci`, затем `npm run verify`; версия выпуска записана в `RELEASE_SOURCE.json`.
Установка из этого каталога: `node install.mjs --project /путь/к/приложению --framework react`.
Для Qwik укажи `--framework qwik`.

- [Выпуски, установка и подключение к Hub](docs/distribution.md)
- [Руководство по компонентам](docs/agent-guide.md)
- [Правила для приложения](AGENTS.md)
- [Лицензия](LICENSE) и [сторонние материалы](THIRD_PARTY_NOTICES.md)
