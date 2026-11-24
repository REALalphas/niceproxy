# Проверки niceproxy

Все стенды создают отдельные процессы, данные и высокие порты. Они не используют
рабочую конфигурацию niceproxy или NAS. Запускать команды из корня репозитория.
Парк использует loopback-IP Linux; это не VM и не моделирование WAN/CGNAT.

## Подготовка

```sh
go build -o bin/niceproxy ./cmd/niceproxy
go build -o bin/parkload ./scripts/parkload
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
```

Нужен проверенный Caddy 2.10.2. Путь передаётся явно во всех командах. Его скачивание
и проверка checksum выполняются отдельно; стенд не устанавливает доверенные CA в ОС.

## Регрессии и парк

```sh
NICEPROXY_CADDY_TEST_BINARY=/path/to/caddy go test -race -count=1 ./...
go vet ./...
npm --prefix web test
python3 scripts/smoke.py --caddy /path/to/caddy
python3 scripts/ownership-smoke.py --caddy /path/to/caddy
python3 scripts/virtual-park.py --caddy /path/to/caddy --instances 6 --clients 128 --cycles 50 --output test-results/park/fleet.json
```

Парк держит все 768 TCP-клиентов открытыми одновременно на шести экземплярах.
Проверяются nonce/payload и разделение бэкендов, HTTP и TLS, чужие Host, смены
назначений, лимиты, обрывы процессов и backend, сохранение сессии и правил,
завершение TCP/UDP-ассоциаций, FD/RSS/threads. Подробности и ограничения —
[virtual-park.md](virtual-park.md).

Наблюдение новых подключений при смене владельца включает несколько отдельных
API-операций отключения, назначения и включения. Между ними порт может быть закрыт;
эти отказы записываются, а не исключаются из измерения. Удерживаемый принятый TCP-поток
проверяется отдельно. Это разные свойства, поэтому успех теста сохранения потока
не означает нулевой отказ новых подключений.

Быстрый запуск только маршрутизации и конкурентных клиентов:

```sh
python3 scripts/virtual-park.py --caddy /path/to/caddy --instances 6 --clients 128 --functional-only
```

Реальный HTTP/3 (нужен curl с HTTP3):

```sh
python3 scripts/http3-smoke.py --caddy /path/to/caddy
```

Он проверяет QUIC с доверенным CA, когда TCP того же порта занят прямым пробросом;
затем — HTTPS по TCP при прямом UDP, плюс чужой Host в HTTP/3 с проверенным SNI.

Для Linux splice:

```sh
go test -c -o /tmp/niceproxy-proxy.test ./internal/proxy
strace -f -e trace=splice -o test-results/splice-bulk.trace /tmp/niceproxy-proxy.test -test.run '^TestTCPBulkSplice$' -test.count=1
```

## Локальная нагрузка

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --seconds 3 --repeats 2 --concurrency 1,16,64 --output test-results/park/benchmark.json
```

Бюджеты Go задаются отдельно: `--backend-gomaxprocs 4`, `--client-gomaxprocs 4`,
`--app-gomaxprocs 4` (niceproxy и унаследованный им Caddy). По умолчанию везде 4,
как в исходной методике. Они меняют окружение только временных дочерних процессов;
стенд не меняет production environment, affinity или настройки ОС. В JSON сохраняются
точные бюджеты, фактические CPU affinity и для каждого прогона CPU seconds,
measurement wall seconds и mean cores: дельты `/proc/PID/stat` niceproxy/backend/Caddy,
для клиента — собственные user+system CPU через `wait4`. Для постоянных процессов
интервал определяется серединами чтений `/proc`, для клиента включает его запуск
и завершение. Это приблизительные показатели, особенно для коротких прогонов:
они не совпадают с внутренним интервалом RPS генератора. Mean cores — CPU seconds /
wall seconds, не процент CPU. JSON также содержит разрешение CPU ticks, CPU quota,
cpuset и throttling всех доступных предков cgroup v2 до/после прогона, унаследованные
GOGC/GOMEMLIMIT/GODEBUG/GOEXPERIMENT и SHA-256 трёх исполняемых файлов.

`--proxy-only` исключает прямые варианты. Явные цели RPS можно проверить так:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases http_keepalive,tcp_256_reused,https_keepalive --seconds 15 --repeats 3 --concurrency 64 --proxy-only --backend-gomaxprocs 4 --client-gomaxprocs 4 --app-gomaxprocs 8 --targets 'tcp_256_reused=70000,http_keepalive=80000,https_keepalive=40000'
```

`passed` означает функциональный успех; `targetPassed` — отдельный результат целей
(`null`, если цели не заданы). Для каждой цели нужен хотя бы один уровень concurrency,
где **все** ожидаемые повторы proxy завершились без ошибок и каждый достиг цели;
среднее и максимум не заменяют эту проверку. `targetAssessment` содержит результат
каждого уровня. Пропущенный case, неполные или повторённые номера повторов не проходят.
Прямые варианты не учитываются. Недостигнутая явная цель даёт ненулевой exit code,
даже если функциональная проверка прошла. HTTP/HTTPS требуют полный ожидаемый prefix
`bench-backend /` и точное число received bytes = succeeded × длина полного тела;
HTTPS сохраняет проверку CA. Проверки валидатора: `python3 -m unittest discover -s scripts/tests`.

Для проверки TCP на порту, назначенном публичным HTTP, есть отдельный режим:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases tcp_256_reused --tcp-on-http-port --seconds 15 --repeats 3 --concurrency 64 --proxy-only --app-gomaxprocs 8 --targets tcp_256_reused=70000
```

Он явно назначает владельца HTTP-порта `direct` перед созданием TCP-правила; HTTP
на этом сокете отсутствует. Для непривилегированного локального стенда используется
случайный высокий порт из диапазона 20000–29999, переданный как `--http-port`.
Это проверка того же выбора владельца, что для публичного 80, а не буквальный bind
на :80 или измерение маршрутизатора. Точный порт и владелец записываются в `listeners`.
Обычный TCP-проброс и этот режим используют один путь `internal/proxy`, без детектора.

Очередь создания UDP проверяется отдельными регрессиями: 64/128 клиентов с одним первым пакетом, задержанный DNS, пределы 32 обработчика/128 заявок/1 МиБ, отмена и смена поколения.

Генератор проверяет содержимое ответов, не повторяет потерянные UDP-пакеты и выдаёт
неуспех при любой ошибке. Измеряются HTTP/1.1 и проверенный HTTPS, новые TCP-соединения,
TCP/UDP request-reply с повторным использованием соединения, TCP payload 64 KiB.
Новые TCP-соединения по умолчанию измеряются короткими окнами в 1 секунду (`--new-connection-seconds`, максимум 1), чтобы ограничивать нагрузку на общую таблицу conntrack. Для прочих режимов действует `--seconds`. Перед прогонами стенд читает conntrack и оставляет запас под новые соединения; при высокой занятости ждёт естественного истечения записей. Он не меняет sysctl и не очищает чужие записи. Предварительная проверка не защищает от независимой нагрузки других программ.

Для каждого режима сохраняются реальные время, успехи/ошибки, payload bytes,
RPS и приближённые p50/p95/p99. Бэкенд без прокси измеряется отдельно там, где
протокол одинаков; для HTTPS нет ложной прямой базы HTTP. Подробности генератора —
[parkload.md](parkload.md).

Параметр `--cases udp_256_reused` позволяет проверить отдельный режим без повтора
всей матрицы. Пример холодных UDP-стартов:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases udp_256_reused --seconds 1 --repeats 5 --concurrency 64 --output test-results/park/udp-cold.json
```

niceproxy, Caddy, backend и генератор делят одну машину. Нагрузка замкнутая
(closed-loop): следующий запрос клиента идёт после ответа, а не по независимому
расписанию. Поэтому такой RPS не доказывает выдерживание заданной внешней интенсивности
или WAN-пропускную способность. Для TCP с указанным исходным IP генератор использует Linux IP_BIND_ADDRESS_NO_PORT; без него bind-before-connect искажает общий пул локальных портов. Сравнение с nginx не проводится. SQLite DB/WAL
сравниваются до/после чистого трафика, без административных мутаций в интервале.

## Rootless-контейнер

Штатная сборка:

```sh
podman build -t localhost/niceproxy:test .
```

Если registry недоступен, есть отдельный диагностический образ из локальных
статических Go/Caddy, готового UI и системного CA bundle:

```sh
python3 scripts/park-container.py --build --caddy /path/to/caddy
python3 scripts/smoke.py --binary scripts/park-container.py --caddy /path/to/caddy
python3 scripts/ownership-smoke.py --binary scripts/park-container.py --caddy /path/to/caddy
```

Контейнер rootless, с host network, `cap_drop ALL`, `no-new-privileges`, лимитами
PID/памяти/FD и монтированием только временного корня конкретного теста. Ни Docker
socket, ни privileged, ни NET_ADMIN не нужны. Он проверяет работу Go/Caddy в контейнере,
но **не** проверяет Node/bootstrap и стадии сборки штатного Dockerfile. Это отдельный
результат, который нельзя выдавать за успешную штатную сборку.

Результаты и журналы сохраняются в `test-results/`. Неуспешные прогоны сохраняйте
отдельно от повторных после исправления — особенно при потерях UDP или отказах bind.
