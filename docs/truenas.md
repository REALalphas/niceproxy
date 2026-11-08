# TrueNAS SCALE

niceproxy проверен как Custom App на SCALE 25.10.4: сборка исходного Dockerfile на NAS, host network и NAS-local bind mount для `/data`. Docker socket и привилегированный режим приложению не нужны.

Перед установкой создайте отдельный dataset и каталог данных с владельцем UID/GID 1000 и правами 0700. Для сборки перенесите исходники на NAS без `.git`, данных, `.env`, node_modules и локальных бинарников; `build.context` должен быть абсолютным NAS-путём. Настройки этого примера предназначены для первоначального запуска из доверенной LAN:

```yaml
services:
  niceproxy:
    build:
      context: /mnt/POOL/apps/niceproxy/source
    image: niceproxy:truenas-local
    pull_policy: build
    user: "1000:1000"
    network_mode: host
    restart: unless-stopped
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      HOME: /data
      NICEPROXY_PANEL_LISTEN: "YOUR_LAN_IP:19080"
      NICEPROXY_HTTP_PORT: "18080"
      NICEPROXY_HTTPS_PORT: "18443"
    volumes:
      - type: bind
        source: /mnt/POOL/apps/niceproxy/data
        target: /data
        bind:
          create_host_path: false
    tmpfs:
      - /run/niceproxy:uid=1000,gid=1000,mode=0700
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    stop_grace_period: 20s
```

Замените POOL, пути и YOUR_LAN_IP. После успешной сборки сохраните отдельный build compose для обновлений, а в рабочем compose удалите `build` и замените `pull_policy` на `never`. Тогда обычный запуск использует уже собранный образ без registry и пересборки. Следующие сборки требуют доступа NAS к базовым образам, Go/npm и Debian repositories.

Такой запуск без capabilities поддерживает listeners от порта 1024. Для стандартных внешних портов можно настроить роутер: внешний 80/TCP → NAS:18080, внешний 443/TCP → NAS:18443 и внешний 443/UDP → NAS:18443 для HTTP/3. HTTP(S) listeners появляются при добавлении маршрутов. Публичный ACME дополнительно требует правильного DNS и прохождения challenge до Caddy. Панель NAS на 80/443 и панель niceproxy на 19080 имеют отдельное назначение; панель niceproxy оставляйте в доверенной административной сети.

Host networking разделяет порты со всеми службами NAS; проверяйте конфликты при создании правил. Контейнер может быть healthy при ошибке отдельного маршрута: сверяйте desired/applied revision и ошибки в UI. Перед обновлением сохраняйте весь `/data` через snapshot или остановку с копированием, включая SQLite WAL, сертификаты и ключ шифрования Cloudflare. Используйте новый тег для релиза и сохраняйте предыдущий до проверки.

В upstream-образе Caddy есть file capabilities; Dockerfile устанавливает бинарник как новый файл, чтобы запуск с `cap_drop: ALL` не завершался `operation not permitted`. Не заменяйте этот шаг прямым COPY поверх исполняемого файла без проверки запуска.
