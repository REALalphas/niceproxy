import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { createRoot } from "react-dom/client";
import { installControlMotion } from "@alpha/core";
import {
  AppShell,
  Badge,
  Button,
  Card,
  Page,
  DrawerButton,
  Icon,
  IconButton,
  Select,
  Stack,
  Switch,
  Text,
  TextArea,
  TextInput,
} from "@alpha/react";
import "@alpha/core/fonts.css";
import "@alpha/core/styles.css";
import "./anti-ddos.css";
import { changeView } from "./view";
import { formatEndpoint } from "./direct-address";
import { RouteForm } from "./RouteForm";
import { Cloudflare } from "./Cloudflare";
import { cloudflareApi, type CertificateStatus } from "./cloudflare-api";
import {
  api,
  type Auth,
  type DirectRule,
  type HttpRoute,
  type PanelDomainSettings,
  type ProxyConfig,
  type PortOwners,
  type PortOwnerSettings,
  type Policy,
  type AntiDDoSConfig,
  type DDoSStatus,
  validPolicy,
  scopes,
  actions,
  units,
  signals,
  type ServiceHealth,
  Unauthorized,
} from "./api";

const err = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось выполнить действие.";
const trafficStages = {
  pre_filter: "До фильтрации",
  accepted: "Принято",
  routed: "Направлено по маршруту",
  forwarded: "Передано на сервер назначения",
  dropped: "Отброшено",
  backend_rejected: "Отклонено сервером назначения",
};

const metricLabels: Record<string, string> = {
  ...trafficStages,
  active: "Активная обработка",
  tcp_new: "Новые TCP-соединения",
  tcp_active: "Активные TCP-соединения",
  tcp_bytes: "Объём TCP-трафика",
  tls_new: "Новые TLS-соединения",
  tls_active: "Активные TLS-соединения",
  tls_sessions: "TLS-сессии",
  first_byte_ms: "Время до первого байта, мс",
  header_ms: "Время до получения заголовков, мс",
  idle_ms: "Время простоя, мс",
  udp_packets: "UDP-пакеты",
  udp_bytes: "Объём UDP-трафика",
  udp_datagram_bytes: "Размер UDP-датаграммы",
  cpu_percent: "Загрузка ЦП, %",
  memory_bytes: "Использование памяти, байт",
  backlog: "Очередь входящих подключений",
  queue: "Глубина очереди",
  http_requests: "HTTP-запросы",
  http_active: "Активные HTTP-запросы",
  http_connection_active: "Активные HTTP-соединения",
  header_bytes: "Размер заголовков, байт",
  body_bytes: "Размер тела запроса, байт",
  response_ms: "Время ответа, мс",
  backend_active: "Активные обращения к серверу назначения",
  backend_tcp_new: "Новые TCP-соединения с сервером назначения",
  backend_tcp_bytes: "TCP-трафик до сервера назначения, байт",
  backend_udp_packets: "UDP-пакеты до сервера назначения",
  backend_udp_bytes: "UDP-трафик до сервера назначения, байт",
  backend_response_ms: "Время ответа сервера назначения, мс",
};
const signalLabels: Record<(typeof signals)[number], string> = {
  tcp_new: metricLabels.tcp_new,
  tls_new: metricLabels.tls_new,
  requests: "Запросы",
  udp_packets: metricLabels.udp_packets,
  udp_bytes: metricLabels.udp_bytes,
  protocol_errors: "Ошибки протокола",
  timeouts: "Истечения тайм-аута",
  short_connections: "Короткие соединения",
  backend_errors: "Ошибки сервера назначения",
  backend_latency_ms: "Задержка сервера назначения, мс",
  pressure: "Нагрузка на ресурсы",
  distinct_sources: "Уникальные источники",
  distinct_subnets: "Уникальные подсети",
  kernel_drops: "Пакеты, отброшенные ядром",
  udp_unanswered: "UDP-запросы без ответа",
};
const scopeLabels: Record<(typeof scopes)[number], string> = {
  ip: "IP-адрес",
  subnet: "Подсеть",
  listener: "Слушатель",
  endpoint: "Маршрут",
  group: "Группа",
  all_instances: "Все экземпляры",
};
const actionLabels: Record<(typeof actions)[number], string> = {
  pass: "Пропустить",
  slow: "Замедлить",
  reject: "Отклонить",
  block: "Заблокировать",
};
const unitLabels: Record<(typeof units)[number], string> = {
  count: "Количество",
  bytes: "Байты",
  ms: "Миллисекунды",
  percent: "Проценты",
};

const listenerMetrics = [
  "tcp_new",
  "tcp_active",
  "tls_new",
  "tls_active",
  "first_byte_ms",
  "header_ms",
  "idle_ms",
  "udp_packets",
  "udp_bytes",
  "udp_datagram_bytes",
  "cpu_percent",
  "memory_bytes",
  "backlog",
  "queue",
];
const tcpMetrics = [
  "tcp_new",
  "tcp_active",
  "tcp_bytes",
  "idle_ms",
  "backend_active",
];
const udpMetrics = [
  "udp_packets",
  "udp_bytes",
  "udp_datagram_bytes",
  "backend_active",
];
const httpMetrics = [
  "http_requests",
  "http_active",
  "http_connection_active",
  "tls_sessions",
  "header_bytes",
  "body_bytes",
  "response_ms",
  "backend_active",
];
function protectionMetrics(route?: HttpRoute | DirectRule) {
  if (!route) return listenerMetrics;
  if (!("host" in route))
    return route.protocol === "tcp" ? tcpMetrics : udpMetrics;
  if (/^tcp:\/\//i.test(route.target))
    return [
      ...httpMetrics,
      "backend_tcp_new",
      "backend_tcp_bytes",
      "backend_response_ms",
    ];
  if (/^udp:\/\//i.test(route.target))
    return [
      ...httpMetrics,
      "backend_udp_packets",
      "backend_udp_bytes",
      "backend_response_ms",
    ];
  return httpMetrics;
}

const defaultPolicy: Policy = {
  detect: false,
  autoFilter: false,
  enforceLimits: false,
};
type Field = {
  key: string;
  label: string;
  choices?: Record<string, string>;
  optional?: boolean;
};
const rateMetrics = new Set([
  "tcp_new",
  "tls_new",
  "udp_packets",
  "udp_bytes",
  "http_requests",
  "backend_tcp_new",
  "backend_udp_packets",
  "backend_udp_bytes",
]);
function metricUnit(metric: string) {
  if (metric.endsWith("_bytes")) return "bytes";
  if (metric.endsWith("_ms")) return "ms";
  if (metric.endsWith("_percent")) return "percent";
  return "count";
}
const policyId = /^[a-zA-Z0-9_.-]{1,64}$/;
const limitFields: Field[] = [
  { key: "id", label: "Идентификатор лимита" },
  { key: "value", label: "Значение" },
  { key: "unit", label: "Единица измерения", choices: unitLabels },
  { key: "windowSeconds", label: "Окно лимита, с", optional: true },
  { key: "burst", label: "Допустимый всплеск", optional: true },
  { key: "scope", label: "Область действия", choices: scopeLabels },
  { key: "action", label: "Действие при превышении", choices: actionLabels },
  { key: "ttlSeconds", label: "Срок действия, с", optional: true },
];
const ruleFields: Field[] = [
  { key: "id", label: "Идентификатор правила" },
  { key: "signal", label: "Сигнал детектора", choices: signalLabels },
  { key: "scope", label: "Область действия", choices: scopeLabels },
  { key: "threshold", label: "Порог срабатывания" },
  { key: "clearThreshold", label: "Порог снятия ограничения" },
  { key: "windowSeconds", label: "Окно наблюдения, с" },
  { key: "burst", label: "Допустимый всплеск" },
  { key: "minSamples", label: "Минимум наблюдений" },
  { key: "action", label: "Действие при срабатывании", choices: actionLabels },
  { key: "cooldownSeconds", label: "Пауза после срабатывания, с" },
];
const numericFields = new Set([
  "value",
  "windowSeconds",
  "burst",
  "ttlSeconds",
  "threshold",
  "clearThreshold",
  "minSamples",
  "cooldownSeconds",
]);
function numberField(value: string, label: string) {
  const number = Number(value.replace(",", "."));
  if (!/^\d+(?:[.,]\d+)?$/.test(value) || !Number.isFinite(number))
    throw new Error(`Укажите неотрицательное число в поле «${label}».`);
  return number;
}
type PolicyRow = { key: string; values: Record<string, string> };
let policyRowSequence = 0;
function newPolicyRow(values: Record<string, string | number>): PolicyRow {
  return {
    key: String(++policyRowSequence),
    values: Object.fromEntries(
      Object.entries(values).map(([key, value]) => [key, String(value)]),
    ),
  };
}
function readPolicyRows(rows: PolicyRow[], fields: Field[]) {
  const ids = new Set<string>();
  return rows.map(({ values }) => {
    const result = Object.fromEntries(
      fields.flatMap(({ key, label, optional }) => {
        const value = values[key]?.trim() ?? "";
        if (!value && optional) return [];
        if (!value) throw new Error(`Заполните поле «${label}».`);
        return [
          [key, numericFields.has(key) ? numberField(value, label) : value],
        ];
      }),
    );
    const id = String(result.id);
    if (!policyId.test(id))
      throw new Error(
        "Идентификатор должен содержать от 1 до 64 латинских букв, цифр, точек, дефисов или подчёркиваний.",
      );
    if (ids.has(id)) throw new Error(`Идентификатор «${id}» повторяется.`);
    ids.add(id);
    return result;
  });
}
function PolicyRows({
  rows,
  fields,
  disabled,
  heading,
  onChange,
  defaults,
}: {
  rows: PolicyRow[];
  fields: Field[];
  disabled: boolean;
  heading: string;
  onChange: (rows: PolicyRow[]) => void;
  defaults: Record<string, string | number>;
}) {
  return (
    <div className="ddos-form-section">
      <Text as="h3">{heading}</Text>
      {rows.map((row, index) => (
        <Card key={row.key}>
          <Stack gap={3}>
            <div className="ddos-row-fields">
              {fields.map(({ key, label, choices, optional }) => {
                const id = `ddos-${row.key}-${key}`;
                const value = row.values[key] ?? "";
                const onValueChange = (next: string) =>
                  onChange(
                    rows.map((item) =>
                      item.key === row.key
                        ? {
                            ...item,
                            values: {
                              ...item.values,
                              ...(key === "metric"
                                ? {
                                    unit: metricUnit(next),
                                    windowSeconds: rateMetrics.has(next)
                                      ? "1"
                                      : "",
                                    burst: "",
                                  }
                                : {}),
                              [key]: next,
                            },
                          }
                        : item,
                    ),
                  );
                return choices ? (
                  <Select
                    key={key}
                    id={id}
                    label={label}
                    value={value}
                    popup="overlay"
                    options={Object.entries(choices).map(([value, label]) => ({
                      value,
                      label,
                    }))}
                    onValueChange={onValueChange}
                    disabled={disabled}
                  />
                ) : (
                  <TextInput
                    key={key}
                    id={id}
                    label={label}
                    value={value}
                    onValueChange={onValueChange}
                    disabled={disabled}
                    required={!optional}
                  />
                );
              })}
            </div>
            <Button
              variant="blank"
              disabled={disabled}
              onPress={() =>
                onChange(rows.filter((item) => item.key !== row.key))
              }
            >
              Удалить запись {index + 1}
            </Button>
          </Stack>
        </Card>
      ))}
      <Button
        disabled={disabled}
        onPress={() => onChange([...rows, newPolicyRow(defaults)])}
      >
        Добавить запись
      </Button>
    </div>
  );
}

export function ProtectionForm({
  initial,
  route,
  onSave,
}: {
  initial?: Policy;
  route?: HttpRoute | DirectRule;
  onSave: (policy: Policy) => Promise<void>;
}) {
  const formId = useId();
  const [policy, setPolicy] = useState(initial ?? defaultPolicy);
  const [stableWindows, setStableWindows] = useState(
    String(initial?.stableWindows ?? ""),
  );
  const [limits, setLimits] = useState(() =>
    (initial?.limits ?? []).map(newPolicyRow),
  );
  const [rules, setRules] = useState(() =>
    (initial?.rules ?? []).map(newPolicyRow),
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const metrics = protectionMetrics(route);
  const hasTLS = route && "host" in route && route.tls !== "off";
  const metricChoices = Object.fromEntries(
    [
      ...new Set([
        ...metrics,
        ...(initial?.limits ?? []).map(({ metric }) => metric),
      ]),
    ].map((metric) => [metric, translated(metricLabels, metric)]),
  );
  const availableScopes = Object.fromEntries(
    Object.entries(scopeLabels).filter(
      ([scope]) => scope !== (route ? "listener" : "endpoint"),
    ),
  );
  const withScopes = (field: Field) =>
    field.key === "scope" ? { ...field, choices: availableScopes } : field;
  const fields = [
    { key: "metric", label: "Метрика лимита", choices: metricChoices },
    ...limitFields.map(withScopes),
  ];
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setMessage("");
    try {
      const next = {
        ...policy,
        stableWindows: stableWindows.trim()
          ? numberField(stableWindows.trim(), "Стабильные окна")
          : undefined,
        limits: readPolicyRows(limits, fields),
        rules: readPolicyRows(rules, ruleFields),
      };
      if (!validPolicy(next))
        throw new Error(
          "Проверьте параметры. Окна, сроки и количество наблюдений задаются целыми числами.",
        );
      if (next.stableWindows !== undefined && next.stableWindows > 60)
        throw new Error("Укажите не более 60 стабильных окон.");
      if (next.group && !policyId.test(next.group))
        throw new Error(
          "Группа должна содержать от 1 до 64 латинских букв, цифр, точек, дефисов или подчёркиваний.",
        );
      const ids = [...next.limits, ...next.rules].map(({ id }) => id);
      if (new Set(ids).size !== ids.length)
        throw new Error(
          "У лимитов и правил должны быть уникальные идентификаторы.",
        );
      for (const limit of next.limits) {
        if (limit.value <= 0 || limit.unit !== metricUnit(limit.metric))
          throw new Error(
            `Проверьте значение и единицу измерения лимита «${limit.id}».`,
          );
        if (rateMetrics.has(limit.metric)) {
          if (!limit.windowSeconds || limit.windowSeconds > 300)
            throw new Error(
              `Для лимита «${limit.id}» укажите окно от 1 до 300 секунд.`,
            );
        } else if (limit.windowSeconds || limit.burst) {
          throw new Error(
            `У лимита «${limit.id}» окно и всплеск доступны только для метрик интенсивности.`,
          );
        }
      }
      for (const rule of next.rules) {
        if (
          rule.windowSeconds < 1 ||
          rule.windowSeconds > 300 ||
          rule.minSamples < 1 ||
          rule.cooldownSeconds < 1 ||
          rule.cooldownSeconds > 86400
        )
          throw new Error(
            `Проверьте окно, минимум наблюдений и паузу у правила «${rule.id}».`,
          );
        if (rule.clearThreshold >= rule.threshold)
          throw new Error(
            `У правила «${rule.id}» порог снятия должен быть меньше порога срабатывания.`,
          );
      }
      setBusy(true);
      await onSave(next);
      setMessage(
        "Настройки сохранены. Состояние применения показано в сводке.",
      );
    } catch (e) {
      setError(err(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack gap={4}>
        <Text as="h2">{route ? "Защита маршрута" : "Защита слушателя"}</Text>
        <div className="ddos-form-section">
          <Text as="h3">Режим защиты</Text>
          <div className="ddos-policy-switches">
            {(
              [
                ["detect", "Обнаружение атак"],
                ["autoFilter", "Автоматическая фильтрация"],
                ["enforceLimits", "Применение лимитов"],
              ] as const
            ).map(([key, label]) => (
              <Switch
                key={key}
                id={`${formId}-${key}`}
                label={label}
                checked={policy[key] ?? false}
                disabled={busy}
                onCheckedChange={(checked) =>
                  setPolicy({ ...policy, [key]: checked })
                }
              />
            ))}
          </div>
        </div>
        <div className="ddos-form-section">
          <Text as="h3">Параметры области</Text>
          <div className="ddos-form-grid">
            <TextInput
              id={`${formId}-stable`}
              label="Количество стабильных окон"
              value={stableWindows}
              onValueChange={setStableWindows}
              disabled={busy}
            />
            <TextInput
              id={`${formId}-group`}
              label="Группа защиты"
              value={policy.group ?? ""}
              onValueChange={(group) => setPolicy({ ...policy, group })}
              disabled={busy}
            />
          </div>
        </div>
        {hasTLS && (
          <div className="ddos-form-section">
            <Text as="h3">Доверие к Cloudflare</Text>
            <Switch
              id={`${formId}-cloudflare-only`}
              label="Разрешать трафик только от Cloudflare"
              checked={policy.cloudflareOnly ?? false}
              disabled={busy}
              onCheckedChange={(cloudflareOnly) =>
                setPolicy({ ...policy, cloudflareOnly })
              }
            />
            <TextArea
              id={`${formId}-origin-ca`}
              label="Сертификат CA для Origin Pull (PEM)"
              value={policy.originPullCA ?? ""}
              onValueChange={(originPullCA) =>
                setPolicy({ ...policy, originPullCA })
              }
              disabled={busy}
            />
          </div>
        )}
        {route && (("host" in route && /^udp:\/\//i.test(route.target)) || (!("host" in route) && route.protocol === "udp")) && (
          <div className="ddos-form-section">
            <Text as="h3">UDP</Text>
            <Switch
              id={`${formId}-udp-response`}
              label="Ожидать ответ UDP"
              checked={policy.expectUDPResponse ?? false}
              disabled={busy}
              onCheckedChange={(expectUDPResponse) => setPolicy({ ...policy, expectUDPResponse })}
            />
          </div>
        )}
        <PolicyRows
          heading="Лимиты"
          rows={limits}
          fields={fields}
          disabled={busy}
          onChange={setLimits}
          defaults={{
            metric: metrics[0],
            value: 1,
            unit: "count",
            windowSeconds: 1,
            scope: route ? "endpoint" : "listener",
            action: "pass",
          }}
        />
        <PolicyRows
          heading="Правила детектора"
          rows={rules}
          fields={ruleFields.map(withScopes)}
          disabled={busy}
          onChange={setRules}
          defaults={{
            signal:
              route && "host" in route
                ? "requests"
                : route?.protocol === "udp"
                  ? "udp_packets"
                  : "tcp_new",
            scope: route ? "endpoint" : "listener",
            threshold: 1,
            clearThreshold: 0,
            windowSeconds: 1,
            burst: 0,
            minSamples: 1,
            action: "pass",
            cooldownSeconds: 60,
          }}
        />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        {message && (
          <div role="status">
            <Text>{message}</Text>
          </div>
        )}
        <Button type="submit" loading={busy} disabled={busy}>
          Сохранить политику
        </Button>
      </Stack>
    </form>
  );
}

const applyLabels = {
  active: "Применено",
  applying: "Применяется",
  partial: "Применено частично",
};
const detectorLabels: Record<string, string> = {
  disabled: "Выключен",
  off: "Выключен",
  learning: "Обучается",
  collecting: "Собирает данные",
  partial: "Частичная видимость трафика",
  warming_up: "Собирает исходные данные",
  normal: "Норма",
  stable: "Норма",
  suspect: "Подозрение на атаку",
  suspected: "Подозрение на атаку",
  suspicious: "Подозрение на атаку",
  attack: "Обнаружена атака",
  mitigation: "Фильтрует трафик",
  mitigating: "Фильтрует трафик",
  cooldown: "Пауза после срабатывания",
  recovering: "Восстановление",
  unavailable: "Нет данных",
};
const observationLabels: Record<string, string> = {
  full: "Полная",
  socket: "Наблюдение на уровне сокетов",
  partial: "Частичная",
  unavailable: "Нет данных",
  none: "Нет данных",
};
const detectorReasons: Record<string, string> = {
  detector_disabled: "Детектор выключен",
  warming_up: "Сбор исходных данных",
  pre_filter_incomplete: "Доступна только часть данных до фильтрации",
  corroborated_rule: "Срабатывание правила подтверждено",
  input_and_backend_stable: "Входящий трафик и сервер назначения стабильны",
  stable_windows_required: "Ожидание стабильных окон наблюдения",
  anomalies_or_resource_pressure: "Аномалии трафика или высокая нагрузка на ресурсы",
  resource_or_backend_observation_missing: "Отсутствуют данные о ресурсах или сервере назначения",
};
const translated = (labels: Record<string, string>, key: string) =>
  Object.hasOwn(labels, key) ? labels[key] : key;
const displayNumber = new Intl.NumberFormat("ru-RU", {
  maximumFractionDigits: 3,
});
const formatMetric = (value: number | null | undefined) =>
  value == null ? "нет данных" : displayNumber.format(value);
const displayTime = (value: string) => new Date(value).toLocaleString("ru-RU");

function StatusItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="ddos-summary-item">
      <div className="ddos-summary-label">
        <Text tone="muted">{label}</Text>
      </div>
      <div className="ddos-summary-value">
        <Text>{children}</Text>
      </div>
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="ddos-detail-row">
      <div className="ddos-detail-label">
        <Text tone="muted">{label}</Text>
      </div>
      <div className="ddos-detail-value">
        <Text>{children}</Text>
      </div>
    </div>
  );
}

function DDoSDashboard({
  status,
  error,
  busy,
  onRefresh,
  onClear,
}: {
  status: DDoSStatus | null;
  error: string;
  busy: boolean;
  onRefresh: () => void;
  onClear: (data: Parameters<typeof api.clearAntiDDoS>[0]) => void;
}) {
  const statusLabel = status ? applyLabels[status.status] : "Нет данных";
  const hasTargets = !!status?.instances.some(
    (instance) => instance.targets.length,
  );
  return (
    <div className="ddos-section-list">
      <Card>
        <Stack gap={4}>
          <div className="ddos-status-toolbar">
            <div className="ddos-status-heading">
              <Stack gap={1}>
                <Text as="h2">Состояние защиты</Text>
                <Text tone="secondary">
                  Применение конфигурации и наблюдаемость экземпляров
                </Text>
              </Stack>
            </div>
            <Badge value={statusLabel} />
            <Button onPress={onRefresh} disabled={busy}>
              Обновить сводку
            </Button>
          </div>
          <div className="ddos-summary-grid">
            <StatusItem label="Желаемая ревизия">
              {status ? status.revision : "нет данных"}
            </StatusItem>
            <StatusItem label="Применённая ревизия">
              {status ? status.appliedRevision : "нет данных"}
            </StatusItem>
            <StatusItem label="Экземпляры">
              {status ? status.instances.length : "нет данных"}
            </StatusItem>
          </div>
          {error && <ErrorMessage>{error}</ErrorMessage>}
          {!status && !error && <Text tone="muted">Состояние применения — нет данных</Text>}
          {status && !hasTargets && (
            <Card>
              <Stack gap={2}>
                <Text as="h3">Нет активных целей наблюдения</Text>
                <div className="ddos-empty">
                  <Text tone="secondary">
                    Метрики появятся после настройки слушателя или маршрута.
                  </Text>
                </div>
              </Stack>
            </Card>
          )}
        </Stack>
      </Card>

      {status?.instances.map((instance) => (
        <Card key={instance.id}>
          <Stack gap={4}>
            <div className="ddos-instance-heading">
              <Stack gap={1}>
                <Text as="h2">Экземпляр {instance.id}</Text>
                <Text tone="secondary">Версия {instance.version}</Text>
              </Stack>
              {instance.error && <Badge value="Ошибка экземпляра" />}
            </div>
            {instance.error && <ErrorMessage>{instance.error}</ErrorMessage>}
            {instance.cloudflare && (
              <Card>
                <Stack gap={3}>
                  <Stack gap={1}>
                    <Text as="h3">Сети Cloudflare</Text>
                    <Text tone="secondary">Доверенные адреса для фильтрации источников</Text>
                  </Stack>
                  <div className="ddos-summary-grid">
                    <StatusItem label="Количество сетей">
                      {formatMetric(
                        typeof instance.cloudflare.networks === "number"
                          ? instance.cloudflare.networks
                          : instance.cloudflare.networks?.length,
                      )}
                    </StatusItem>
                    <StatusItem label="Обновлено">
                      {instance.cloudflare.updatedAt
                        ? displayTime(instance.cloudflare.updatedAt)
                        : "нет данных"}
                    </StatusItem>
                    <StatusItem label="Источник">
                      {instance.cloudflare.ipv4URL || instance.cloudflare.ipv6URL || "не настроен"}
                    </StatusItem>
                  </div>
                  {instance.cloudflare.error && <ErrorMessage>{instance.cloudflare.error}</ErrorMessage>}
                </Stack>
              </Card>
            )}
            {!instance.targets.length && <Text tone="muted">Цели наблюдения — нет данных</Text>}
            <div className="ddos-target-list">
              {instance.targets.map((target) => (
                <Card key={target.id}>
                  <Stack gap={4}>
                    <div className="ddos-target-heading">
                      <Stack gap={1}>
                        <Text as="h2">{target.label || target.id}</Text>
                        <Text tone="secondary">Цель {target.id}</Text>
                      </Stack>
                      <Badge value={translated(detectorLabels, target.state)} />
                    </div>
                    <div className="ddos-target-summary">
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Оценка детектора</Text>
                        <Text font="mono">{formatMetric(target.score)}</Text>
                      </div>
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Причина</Text>
                        <Text>{target.reason ? translated(detectorReasons, target.reason) : "нет данных"}</Text>
                      </div>
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Наблюдаемость</Text>
                        <Text>{translated(observationLabels, target.observability)}</Text>
                      </div>
                    </div>
                    <Card>
                      <Stack gap={2}>
                        <Text as="h3">Применённая политика</Text>
                        <Text>
                          Обнаружение {target.policy.detect ? "включено" : "выключено"} · автофильтрация {target.policy.autoFilter ? "включена" : "выключена"} · лимиты {target.policy.enforceLimits ? "включены" : "выключены"}
                        </Text>
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Этапы обработки и метрики</Text>
                        <div className="ddos-metric-list">
                          {[...new Set([...Object.keys(trafficStages), ...Object.keys(target.metrics)])].map((key) => {
                            const metric = target.metrics[key];
                            return (
                              <div className="ddos-metric-row" key={key}>
                                <div className="ddos-metric-label">
                                  <Text>{translated(metricLabels, key)}</Text>
                                </div>
                                <div className="ddos-metric-value">
                                  <Text font="mono">{formatMetric(metric?.value)}</Text>
                                </div>
                                <div className="ddos-metric-source">
                                  <Text tone="muted">{metric?.source ? `Источник: ${metric.source}` : "Источник не указан"}</Text>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Активные лимиты</Text>
                        {!target.policy.enforceLimits ? (
                          <Text tone="muted">Применение лимитов выключено</Text>
                        ) : target.policy.limits?.length ? (
                          <div className="ddos-detail-list">
                            {target.policy.limits.map((limit) => (
                              <DetailRow key={limit.id} label={limit.id}>
                                {translated(metricLabels, limit.metric)} · {formatMetric(limit.value)} {unitLabels[limit.unit]} · {scopeLabels[limit.scope]} · {actionLabels[limit.action]}{limit.windowSeconds !== undefined ? ` · окно ${limit.windowSeconds} с` : ""}
                              </DetailRow>
                            ))}
                          </div>
                        ) : (
                          <Text tone="muted">Лимиты не заданы</Text>
                        )}
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Активные ограничения</Text>
                        {!target.restrictions?.length && <Text tone="muted">Ограничений нет</Text>}
                        {target.restrictions?.map((restriction, index) => (
                          <Stack key={index} gap={2}>
                            <DetailRow label={`${actionLabels[restriction.action]} · ${scopeLabels[restriction.scope]}`}>
                              {restriction.target} · правило {restriction.rule} · до {displayTime(restriction.expiresAt)} · {restriction.automatic ? "автоматическое" : "ручное"}
                            </DetailRow>
                            {restriction.automatic && (
                              <Button
                                variant="blank"
                                disabled={busy}
                                onPress={() => onClear({
                                  instance: instance.id,
                                  target: target.id,
                                  rule: restriction.rule,
                                  subject: restriction.target,
                                  ttlSeconds: 60,
                                })}
                              >
                                Снять ограничение на 60 секунд
                              </Button>
                            )}
                          </Stack>
                        ))}
                      </Stack>
                    </Card>
                    {!!target.events?.length && (
                      <Card>
                        <Stack gap={3}>
                          <Text as="h3">События детектора</Text>
                          <div className="ddos-detail-list">
                            {target.events.map((event, index) => (
                              <DetailRow key={index} label={displayTime(event.at)}>
                                {actionLabels[event.action]} · {event.reason} {event.rules?.join(", ")}
                              </DetailRow>
                            ))}
                          </div>
                        </Stack>
                      </Card>
                    )}
                    {!!target.history?.length && (
                      <Card>
                        <Stack gap={3}>
                          <Text as="h3">История нагрузки</Text>
                          <div className="ddos-detail-list">
                            {target.history.map((point, index) => (
                              <DetailRow key={index} label={displayTime(point.at)}>
                                {formatMetric(point.load)} · норма {formatMetric(point.normalLow)}–{formatMetric(point.normalHigh)}
                              </DetailRow>
                            ))}
                          </div>
                        </Stack>
                      </Card>
                    )}
                    {!!target.sources?.length && (
                      <Card>
                        <Stack gap={3}>
                          <Text as="h3">Источники трафика</Text>
                          <div className="ddos-detail-list">
                            {target.sources.map((origin, index) => (
                              <DetailRow key={index} label={`${origin.address} · ${origin.subnet}`}>
                                {formatMetric(origin.count)}{origin.reason ? ` · ${origin.reason}` : ""}
                              </DetailRow>
                            ))}
                          </div>
                        </Stack>
                      </Card>
                    )}
                  </Stack>
                </Card>
              ))}
            </div>
          </Stack>
        </Card>
      ))}
    </div>
  );
}

function CloudflareProtectionForm({
  initial,
  onSave,
}: {
  initial?: AntiDDoSConfig["cloudflare"];
  onSave: (value: NonNullable<AntiDDoSConfig["cloudflare"]>) => Promise<void>;
}) {
  const [enabled, setEnabled] = useState(initial?.enabled ?? false);
  const [ipv4URL, setIPv4] = useState(initial?.ipv4URL ?? "");
  const [ipv6URL, setIPv6] = useState(initial?.ipv6URL ?? "");
  const [proxies, setProxies] = useState(
    initial?.trustedProxies?.join(", ") ?? "",
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  return (
    <form
      onSubmit={async (event) => {
        event.preventDefault();
        if (busy) return;
        setBusy(true);
        setError("");
        setMessage("");
        try {
          await onSave({
            enabled,
            ipv4URL: ipv4URL.trim(),
            ipv6URL: ipv6URL.trim(),
            trustedProxies: proxies
              .split(",")
              .map((value) => value.trim())
              .filter(Boolean),
          });
          setMessage(
            "Настройки сохранены. Состояние применения показано в сводке.",
          );
        } catch (e) {
          setError(err(e));
        } finally {
          setBusy(false);
        }
      }}
    >
      <Stack gap={3}>
        <Text as="h2">Доверенные сети Cloudflare</Text>
        <Switch
          id="ddos-cf"
          label="Включить доверие к сетям Cloudflare"
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-ipv4"
          type="url"
          label="URL списка сетей IPv4"
          value={ipv4URL}
          onValueChange={setIPv4}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-ipv6"
          type="url"
          label="URL списка сетей IPv6"
          value={ipv6URL}
          onValueChange={setIPv6}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-proxies"
          label="Доверенные прокси через запятую"
          value={proxies}
          onValueChange={setProxies}
          disabled={busy}
        />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        {message && (
          <div role="status">
            <Text>{message}</Text>
          </div>
        )}
        <Button type="submit" loading={busy} disabled={busy}>
          Сохранить сети Cloudflare
        </Button>
      </Stack>
    </form>
  );
}

function ProtectionSettings({
  config,
  route,
  cloudflare,
  onSaved,
}: {
  config: ProxyConfig;
  route?: HttpRoute | DirectRule;
  cloudflare: boolean;
  onSaved: (next: ProxyConfig) => void;
}) {
  const [base, setBase] = useState(config);
  const desired = base.antiDDoS;
  async function save(settings: AntiDDoSConfig) {
    const next = await api.saveAntiDDoS({
      ...desired,
      ...settings,
      revision: base.revision,
    });
    setBase(next);
    onSaved(next);
  }
  return cloudflare ? (
    <CloudflareProtectionForm
      initial={desired?.cloudflare}
      onSave={(value) => save({ cloudflare: value })}
    />
  ) : (
    <ProtectionForm
      initial={route ? desired?.endpoints?.[route.id] : desired?.listener}
      route={route}
      onSave={(policy) =>
        save(
          route
            ? { endpoints: { ...desired?.endpoints, [route.id]: policy } }
            : { listener: policy },
        )
      }
    />
  );
}

function AntiDDoSPage({
  config,
  onSaved,
}: {
  config: ProxyConfig;
  onSaved: (next: ProxyConfig) => void;
}) {
  const [editor, setEditor] = useState("listener");
  const [status, setStatus] = useState<DDoSStatus | null>(null);
  const [readError, setReadError] = useState("");
  const [clearError, setClearError] = useState("");
  const [clearing, setClearing] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [editorVersion, setEditorVersion] = useState(0);
  const routes = [...config.httpRoutes, ...config.directRules];
  const route = routes.find((item) => `route:${item.id}` === editor);
  const selected = route || editor === "cloudflare" ? editor : "listener";
  useEffect(() => {
    let live = true;
    let timer: number;
    async function read() {
      try {
        const next = await api.antiDDoS();
        if (!live) return;
        setStatus(next);
        setReadError("");
      } catch (e) {
        if (!live) return;
        setStatus(null);
        setReadError(err(e));
      }
      if (live) timer = window.setTimeout(() => void read(), 5000);
    }
    void read();
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [refresh]);
  async function clear(data: Parameters<typeof api.clearAntiDDoS>[0]) {
    if (clearing) return;
    setClearError("");
    setClearing(true);
    try {
      await api.clearAntiDDoS(data);
      setRefresh((current) => current + 1);
    } catch (e) {
      setClearError(err(e));
    } finally {
      setClearing(false);
    }
  }
  return (
    <div className="ddos-page">
      <Stack gap={4}>
        <Card>
          <Stack gap={4}>
            <div className="ddos-editor-toolbar">
              <div className="ddos-editor-select">
                <Select
                  id="ddos-editor"
                  label="Область настройки защиты"
                  value={selected}
                  onValueChange={setEditor}
                  popup="overlay"
                  options={[
                    { value: "listener", label: "Глобальный слушатель" },
                    { value: "cloudflare", label: "Доверенные сети Cloudflare" },
                    ...routes.map((item) => ({
                      value: `route:${item.id}`,
                      label: `Маршрут · ${source(item)}`,
                    })),
                  ]}
                />
              </div>
              <Button
                variant="blank"
                onPress={() => setEditorVersion((current) => current + 1)}
              >
                Сбросить правки
              </Button>
            </div>
            <ProtectionSettings
              key={`${selected}:${editorVersion}`}
              config={config}
              route={route}
              cloudflare={selected === "cloudflare"}
              onSaved={(next) => {
                onSaved(next);
                setRefresh((current) => current + 1);
              }}
            />
          </Stack>
        </Card>
        {clearError && <ErrorMessage>{clearError}</ErrorMessage>}
        <DDoSDashboard
          status={status}
          error={readError}
          busy={clearing}
          onRefresh={() => setRefresh((current) => current + 1)}
          onClear={(data) => void clear(data)}
        />
      </Stack>
    </div>
  );
}

function ErrorMessage({ children }: { children: string }) {
  return (
    <div role="alert">
      <Text>{children}</Text>
    </div>
  );
}
function AuthScreen({
  initial,
  onAuthenticated,
}: {
  initial: Auth;
  onAuthenticated: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError("");
    try {
      await api.login(password, !initial.configured);
      onAuthenticated();
    } catch (e) {
      setError(err(e));
      setBusy(false);
    }
  }
  return (
    <main className="alpha-ui">
      <Page width="form" align="center" viewport="full">
        <Card>
          <Stack gap={6}>
            <Text font="heading" size="title" weight="bold">
              Niceproxy
            </Text>
            <form onSubmit={submit}>
              <Stack gap={4}>
                <Text as="h1" font="heading" size="title">
                  {initial.configured
                    ? "Вход в Niceproxy"
                    : "Первичная настройка"}
                </Text>
                <Text tone="secondary">
                  {initial.configured
                    ? "Введите пароль администратора."
                    : "Создайте пароль администратора: от 12 до 72 байт."}
                </Text>
                <TextInput
                  showIcon
                  id="password"
                  label="Пароль"
                  labelPlacement="inside"
                  type="password"
                  value={password}
                  onValueChange={setPassword}
                  autoComplete={
                    initial.configured ? "current-password" : "new-password"
                  }
                  required
                  disabled={busy}
                />
                {error && <ErrorMessage>{error}</ErrorMessage>}
                <Button type="submit" loading={busy}>
                  {initial.configured ? "Войти" : "Сохранить пароль"}
                </Button>
              </Stack>
            </form>
          </Stack>
        </Card>
      </Page>
    </main>
  );
}
function statusLabel(route: HttpRoute | DirectRule) {
  return !route.enabled
    ? "Выключен"
    : route.status === "healthy"
      ? "Применён"
      : route.status === "waiting_acme"
        ? "Ожидание сертификата"
        : route.status === "waiting_dns"
          ? "Ожидание DNS"
          : route.status === "invalid_certificate"
            ? "Недействительный сертификат"
            : route.status === "error"
              ? "Ошибка применения"
              : "Не подтверждён";
}
type Mapping = {
  key: string;
  kind: "http-routes" | "direct-rules";
  route: HttpRoute | DirectRule;
};
function source(route: HttpRoute | DirectRule) {
  return "host" in route
    ? `${route.host}${route.path === "/" ? "" : route.path}`
    : `${route.protocol.toUpperCase()} ${formatEndpoint(route.listenHost, route.listenPort)}`;
}
function target(route: HttpRoute | DirectRule) {
  return "host" in route
    ? route.target
    : formatEndpoint(route.targetHost, route.targetPort);
}
function publicPortLines(
  route: HttpRoute | DirectRule,
  settings: PortOwnerSettings | null,
) {
  if (!("host" in route)) return [];
  if (!settings) return ["Публичные порты настраиваются автоматически"];
  const label = (owner: PortOwners[keyof PortOwners]) =>
    owner === "direct" ? "Прямой проброс" : "Веб-доступ";
  if (route.tls === "off")
    return [`HTTP · TCP ${settings.httpPort} · ${label(settings.owners.http)}`];
  return [
    `HTTPS · TCP ${settings.httpsPort} · ${label(settings.owners.https)}`,
    `HTTP/3 · UDP ${settings.httpsPort} · ${label(settings.owners.http3)}`,
  ];
}
function readPage() {
  const hash = window.location.hash.slice(1);
  if (hash === "cloudflare" || hash === "settings/cloudflare")
    return "settings/cloudflare";
  if (
    hash === "settings/anti-ddos" ||
    hash === "settings/account" ||
    hash === "settings"
  )
    return hash;
  if (hash === "overview") return "overview";
  if (hash.startsWith("routes/")) return hash;
  return "routes";
}
function App() {
  const [auth, setAuth] = useState<Auth | null>(null);
  const [config, setConfig] = useState<ProxyConfig | null>(null);
  const [health, setHealth] = useState<ServiceHealth | null>(null);
  const [certificate, setCertificate] = useState<CertificateStatus | null>(
    null,
  );
  const [panelDomainSettings, setPanelDomainSettings] =
    useState<PanelDomainSettings | null>(null);
  const [owners, setOwners] = useState<PortOwnerSettings | null>(null);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [pending, setPending] = useState(false);
  const [page, setPage] = useState(readPage);
  const [filter, setFilter] = useState("all");
  const authenticated = useRef(false);
  const epoch = useRef(0);
  const inFlight = useRef<{ version: number; promise: Promise<void> } | null>(
    null,
  );
  const refreshAgain = useRef(false);
  const dataVersion = useRef(0);
  const currentPage = useRef(page);
  const [cloudflareCallback] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const value = params.get("cloudflare");
    if (params.has("cloudflare"))
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.hash,
      );
    return value === "connected" || value === "error" ? value : undefined;
  });
  const refresh = useCallback((foreground = false): Promise<void> => {
    if (!authenticated.current) return Promise.resolve();
    const version = epoch.current;
    if (foreground) setRefreshing(true);
    if (inFlight.current?.version === version) {
      refreshAgain.current = true;
      return inFlight.current.promise;
    }
    const promise = (async () => {
      do {
        refreshAgain.current = false;
        const readingVersion = dataVersion.current;
        const [c, h, o, cert, panel] = await Promise.allSettled([
          api.config(),
          api.health(),
          api.portOwners(),
          cloudflareApi.certificate(),
          api.panelDomain(),
        ]);
        if (version !== epoch.current) return;
        if (readingVersion !== dataVersion.current) continue;
        if (c.status === "fulfilled") setConfig(c.value);
        if (h.status === "fulfilled") setHealth(h.value);
        else setHealth(null);
        if (cert.status === "fulfilled") setCertificate(cert.value);
        else setCertificate(null);
        if (panel.status === "fulfilled") setPanelDomainSettings(panel.value);
        else setPanelDomainSettings(null);
        if (o.status === "fulfilled") {
          setOwners(o.value);
        } else setOwners(null);
        const failure =
          c.status === "rejected"
            ? c.reason
            : h.status === "rejected"
              ? h.reason
              : null;
        setError(
          failure && !(failure instanceof Unauthorized) ? err(failure) : "",
        );
      } while (refreshAgain.current && authenticated.current);
    })().finally(() => {
      if (version === epoch.current) setRefreshing(false);
      if (inFlight.current?.version === version) inFlight.current = null;
    });
    inFlight.current = { version, promise };
    return promise;
  }, []);
  const initialize = useCallback(async () => {
    const version = ++epoch.current;
    try {
      const a = await api.auth();
      if (version !== epoch.current) return;
      authenticated.current = a.authenticated;
      setAuth(a);
      if (a.authenticated) await refresh();
    } catch (e) {
      if (version === epoch.current && !(e instanceof Unauthorized))
        setError(err(e));
    }
  }, [refresh]);
  useEffect(() => {
    void initialize();
    const unauthorized = () => {
      ++epoch.current;
      authenticated.current = false;
      setAuth({ configured: true, authenticated: false });
      setConfig(null);
      setHealth(null);
      setOwners(null);
      setPending(false);
      setError("");
    };
    const changed = (event: Event) => {
      const path =
        event instanceof CustomEvent ? event.detail?.path : undefined;
      if (
        typeof path === "string" &&
        (path.startsWith("/cloudflare") ||
          path === "/login" ||
          path === "/setup" ||
          path === "/logout")
      )
        return;
      if (authenticated.current) {
        ++dataVersion.current;
        void refresh();
      }
    };
    window.addEventListener("niceproxy:unauthorized", unauthorized);
    window.addEventListener("niceproxy:changed", changed);
    return () => {
      ++epoch.current;
      window.removeEventListener("niceproxy:unauthorized", unauthorized);
      window.removeEventListener("niceproxy:changed", changed);
    };
  }, [initialize, refresh]);
  const show = useCallback((next: string) => {
    if (currentPage.current === next) return;
    currentPage.current = next;
    void changeView(() => {
      setPage(next);
      setError("");
    });
  }, []);
  useEffect(() => {
    const changed = () => show(readPage());
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, [show]);
  function navigate(next: string) {
    if (next === currentPage.current) return;
    window.history.pushState(
      null,
      "",
      `#${next === "settings/cloudflare" ? "cloudflare" : next}`,
    );
    show(next);
  }
  async function logout() {
    if (pending) return;
    setPending(true);
    try {
      await api.logout();
      ++epoch.current;
      authenticated.current = false;
      setAuth({ configured: true, authenticated: false });
      setConfig(null);
      setHealth(null);
      setOwners(null);
    } catch (e) {
      setError(err(e));
    } finally {
      setPending(false);
    }
  }
  async function mutate(run: () => Promise<unknown>, done?: () => void) {
    if (pending) return;
    const version = epoch.current;
    setPending(true);
    setError("");
    try {
      await run();
      if (version === epoch.current && authenticated.current) done?.();
    } catch (e) {
      if (version === epoch.current && !(e instanceof Unauthorized))
        setError(err(e));
    } finally {
      if (version === epoch.current) setPending(false);
    }
  }
  if (auth && !auth.authenticated)
    return (
      <AuthScreen initial={auth} onAuthenticated={() => void initialize()} />
    );
  if (!config)
    return (
      <main className="alpha-ui">
        <Page width="form" align="center" viewport="full">
          <Card>
            <Stack gap={4}>
              <Text as="h1" size="title" font="heading">
                Niceproxy
              </Text>
              <Text>{error || "Подключение к сервису…"}</Text>
              {error && (
                <Button onPress={() => void initialize()}>Повторить</Button>
              )}
            </Stack>
          </Card>
        </Page>
      </main>
    );
  const mappings: Mapping[] = [
    ...config.httpRoutes.map((route) => ({
      key: `http/${encodeURIComponent(route.id)}`,
      kind: "http-routes" as const,
      route,
    })),
    ...config.directRules.map((route) => ({
      key: `direct/${encodeURIComponent(route.id)}`,
      kind: "direct-rules" as const,
      route,
    })),
  ];
  const visible = mappings.filter(
    ({ route }) =>
      filter === "all" ||
      ("host" in route ? filter === "http" : filter === route.protocol),
  );
  const section = page.startsWith("settings")
    ? "settings"
    : page === "overview"
      ? "overview"
      : "routes";
  const mode = page.split("/")[1];
  const selectedKey = page.split("/").slice(2).join("/");
  const mapping = mappings.find((item) => item.key === selectedKey);
  const isList = page === "routes";
  const isCreating = mode === "new";
  const routeScreen = section === "routes" && !isList && !isCreating;
  const systemRoute =
    mapping && "host" in mapping.route && mapping.route.systemManaged;
  const isEditing = routeScreen && mode === "edit" && !systemRoute;
  const newProtocol =
    selectedKey === "direct"
      ? filter === "udp" ? "udp" : "tcp"
      : selectedKey === "tcp" || selectedKey === "udp"
        ? selectedKey
        : "http";
  const title =
    page === "overview"
      ? "Сервис"
      : page === "settings/anti-ddos"
        ? "Защита от DDoS"
        : page === "settings/cloudflare"
            ? "Cloudflare DNS"
            : page === "settings/account"
              ? "Доступ к панели"
              : page === "settings"
                ? "Настройки"
                : isList
                  ? "Маршруты"
                  : isCreating
                    ? page.endsWith("/http")
                      ? "Новый HTTP/HTTPS маршрут"
                      : page.endsWith("/direct") ||
                          page.endsWith("/tcp") ||
                          page.endsWith("/udp")
                        ? "Новое TCP/UDP правило"
                        : "Новый маршрут"
                    : mode === "edit"
                      ? "Редактирование маршрута"
                      : mode === "delete"
                        ? "Удаление маршрута"
                        : "Маршрут";
  const converged =
    !!health &&
    health.appliedRevision === config.revision &&
    health.revision === config.revision;
  const applied = converged && health?.status === "healthy";
  const panelAutomation = panelDomainSettings?.automation;
  const cloudflareSSLMode = panelAutomation?.zoneSSL;
  const cloudflareSSLLabel =
    cloudflareSSLMode === "strict"
      ? "Full (strict)"
      : cloudflareSSLMode === "full"
        ? "Full"
        : cloudflareSSLMode === "flexible"
          ? "Flexible"
          : cloudflareSSLMode === "off"
            ? "Off"
            : cloudflareSSLMode === "origin_pull"
              ? "Strict (SSL-Only Origin Pull)"
              : cloudflareSSLMode;
  const renderEpoch = epoch.current;
  const saved = (item: HttpRoute | DirectRule) => {
    if (renderEpoch !== epoch.current || !authenticated.current) return;
    const isHttp = "host" in item;
    setConfig(
      (current) =>
        current && {
          ...current,
          httpRoutes:
            isHttp
              ? [
                  ...current.httpRoutes.filter((r) => r.id !== item.id),
                  item,
                ]
              : current.httpRoutes,
          directRules:
            isHttp
              ? current.directRules
              : [
                  ...current.directRules.filter((r) => r.id !== item.id),
                  item,
                ],
        },
    );
    navigate(`routes/view/${isHttp ? "http" : "direct"}/${encodeURIComponent(item.id)}`);
  };
  return (
    <AppShell
      serviceName="Niceproxy"
      width="container"
      viewport="full"
      serviceMode="static"
      showAccount
      accountLabel="Аккаунт администратора"
      items={[
        { id: "routes", label: "Маршруты", icon: "link" },
        { id: "overview", label: "Сервис", icon: "device" },
        { id: "settings", label: "Настройки", icon: "settings" },
      ]}
      selectedId={section}
      onSelect={navigate}
      onServicePress={() => navigate("routes")}
      onAccountPress={() => navigate("settings/account")}
    >
      <Page
        width={isList || page === "settings/anti-ddos" ? "content" : "form"}
        gap={6}
      >
        <Stack gap={3}>
          {page !== section && (
            <Button
              variant="blank"
              onPress={() =>
                navigate(
                  routeScreen && mode !== "view" && mapping
                    ? `routes/view/${mapping.key}`
                    : section,
                )
              }
            >
              Назад
            </Button>
          )}
          <Text as="h1">{title}</Text>
          {isList && (
            <Stack direction="row" gap={3} align="center">
              <Button
                onPress={() =>
                  navigate(
                    filter === "all" ? "routes/new" : `routes/new/${filter}`,
                  )
                }
              >
                Добавить маршрут
              </Button>
              <IconButton
                icon="refresh"
                label="Обновить маршруты"
                disabled={refreshing}
                onPress={() => void refresh(true)}
              />
            </Stack>
          )}
        </Stack>
        {error && <ErrorMessage>{error}</ErrorMessage>}
        {isList && (
          <Stack gap={5}>
            <Stack direction="row" gap={3} align="center">
              <Select
                popup="overlay"
                id="route-filter"
                label="Протокол"
                variant="plain"
                value={filter}
                onValueChange={setFilter}
                options={[
                  { value: "all", label: "Все протоколы" },
                  { value: "http", label: "HTTP/HTTPS" },
                  { value: "tcp", label: "TCP" },
                  { value: "udp", label: "UDP" },
                ]}
              />
              <Text tone="muted">
                {visible.length} из {mappings.length}
              </Text>
            </Stack>
            {visible.length ? (
              <Stack gap={4}>
                {visible.map(({ key, route }) => (
                  <Card key={key}>
                    <Stack gap={3}>
                      <Stack direction="row" gap={3} align="center">
                        <Icon name={"host" in route ? "link" : "device"} />
                        <Text font="heading" weight="bold">
                          {"host" in route
                            ? route.tls === "off"
                              ? "HTTP"
                              : "HTTPS"
                            : route.protocol.toUpperCase()}
                        </Text>
                        <Text tone="secondary">{statusLabel(route)}</Text>
                      </Stack>
                      <Text font="mono">{source(route)}</Text>
                      <Stack gap={1}>
                        <Text tone="muted">Сервис</Text>
                        <Text font="mono">{target(route)}</Text>
                      </Stack>
                      <Button
                        variant="simple"
                        onPress={() => navigate(`routes/view/${key}`)}
                      >
                        Открыть маршрут
                      </Button>
                    </Stack>
                  </Card>
                ))}
              </Stack>
            ) : (
              <Card>
                <Stack gap={2}>
                  <Text as="h2" size="xl">
                    {mappings.length
                      ? "Нет маршрутов этого типа"
                      : "Подключите первый сервис"}
                  </Text>
                  <Text tone="secondary">
                    {mappings.length
                      ? "Выберите другой протокол или добавьте маршрут."
                      : "HTTP/HTTPS — по домену и пути. TCP/UDP — по порту."}
                  </Text>
                </Stack>
              </Card>
            )}
          </Stack>
        )}
        {isCreating && (
          <RouteForm
            key={page}
            initialProtocol={newProtocol}
            ports={owners}
            onDone={saved}
            onCancel={() => navigate("routes")}
          />
        )}
        {routeScreen && !mapping && (
          <Card>
            <Stack gap={3}>
              <Text>Маршрут не найден.</Text>
              <Button onPress={() => navigate("routes")}>К маршрутам</Button>
            </Stack>
          </Card>
        )}
        {mapping && isEditing && (
          <RouteForm
            key={mapping.key}
            route={mapping.route}
            ports={owners}
            onDone={saved}
            onCancel={() => navigate(`routes/view/${mapping.key}`)}
          />
        )}
        {routeScreen && mapping && !isEditing && (
          <Card>
            {mode === "delete" && !systemRoute ? (
              <Stack gap={4}>
                <Text font="mono">{source(mapping.route)}</Text>
                <Text>
                  Удалить маршрут? Новые подключения перестанут обслуживаться.
                </Text>
                <Stack direction="row" gap={3}>
                  <Button
                    loading={pending}
                    onPress={() =>
                      void mutate(
                        () => api.remove(mapping.kind, mapping.route.id),
                        () => navigate("routes"),
                      )
                    }
                  >
                    Удалить маршрут
                  </Button>
                  <Button
                    variant="blank"
                    disabled={pending}
                    onPress={() => navigate(`routes/view/${mapping.key}`)}
                  >
                    Отмена
                  </Button>
                </Stack>
              </Stack>
            ) : (
              <Stack gap={5}>
                <Stack gap={1}>
                  <Text tone="secondary">Входящий адрес</Text>
                  <Text font="mono" size="lg">
                    {source(mapping.route)}
                  </Text>
                </Stack>
                {publicPortLines(mapping.route, owners).length > 0 && (
                  <Stack gap={1}>
                    <Text tone="secondary">Публичные порты</Text>
                    {publicPortLines(mapping.route, owners).map((line) => (
                      <Text key={line} font="mono">
                        {line}
                      </Text>
                    ))}
                  </Stack>
                )}
                <Stack gap={1}>
                  <Text tone="secondary">Сервис</Text>
                  <Text font="mono" size="lg">
                    {target(mapping.route)}
                  </Text>
                </Stack>
                <Stack direction="row" gap={3} align="center">
                  <Icon
                    name={
                      mapping.route.status === "error"
                        ? "info"
                        : mapping.route.enabled
                          ? "check"
                          : "pause"
                    }
                  />
                  <Text>{statusLabel(mapping.route)}</Text>
                </Stack>
                {mapping.route.error && (
                  <ErrorMessage>{mapping.route.error}</ErrorMessage>
                )}
                {"host" in mapping.route ? (
                  <Text tone="secondary">
                    {mapping.route.tls === "auto"
                      ? "Автоматический TLS"
                      : mapping.route.tls === "internal"
                        ? "Внутренний сертификат"
                        : "Без TLS"}{" "}
                    ·{" "}
                    {mapping.route.stripPrefix
                      ? "Префикс пути удаляется"
                      : "Путь сохраняется"}
                  </Text>
                ) : (
                  <Text tone="secondary">
                    {mapping.route.stats
                      ? `Активно ${mapping.route.stats.active} · всего ${mapping.route.stats.accepted} · ошибок ${mapping.route.stats.errors} · отклонено ${mapping.route.stats.rejects}. ${mapping.route.protocol === "udp" ? "UDP-сессии" : "TCP-соединения"} с запуска процесса.`
                      : "Статистика недоступна"}
                  </Text>
                )}
                {!systemRoute && (
                  <Switch
                    id="route-enabled"
                    label="Маршрут включён"
                    checked={mapping.route.enabled}
                    disabled={pending}
                    onCheckedChange={(enabled) =>
                      void mutate(() =>
                        api.toggle(mapping.kind, mapping.route.id, enabled),
                      )
                    }
                  />
                )}
                {systemRoute && (
                  <Text tone="secondary">
                    Системный маршрут панели управляется настройкой домена
                    панели.
                  </Text>
                )}
                <Stack direction="row" gap={3}>
                  {!systemRoute && (
                    <Button
                      variant="simple"
                      onPress={() => navigate(`routes/edit/${mapping.key}`)}
                    >
                      Изменить
                    </Button>
                  )}
                  <Button
                    variant="blank"
                    onPress={() => void refresh(true)}
                    loading={refreshing}
                  >
                    Обновить
                  </Button>
                  {!systemRoute && (
                    <Button
                      variant="blank"
                      onPress={() => navigate(`routes/delete/${mapping.key}`)}
                    >
                      Удалить
                    </Button>
                  )}
                </Stack>
              </Stack>
            )}
          </Card>
        )}
        {page === "overview" && (
          <Card>
            <Stack gap={5}>
              <Stack gap={2}>
                <Text as="h2" size="xl" font="heading">
                  {!health
                    ? "Состояние недоступно"
                    : health.state === "invalid_certificate" && converged
                      ? "Недействительный сертификат панели"
                      : health.state === "waiting_acme" && converged
                        ? "Ожидание публичного сертификата"
                        : applied
                          ? "Конфигурация применена"
                          : health.status === "error"
                            ? "Ошибка применения"
                            : "Конфигурация применена частично"}
                </Text>
                <Text tone="secondary">
                  Сохранено:{" "}
                  <Text as="span" font="mono">
                    {config.revision}
                  </Text>{" "}
                  · применено:{" "}
                  <Text as="span" font="mono">
                    {health
                      ? health.appliedRevision < 0
                        ? "частично"
                        : health.appliedRevision
                      : "неизвестно"}
                  </Text>
                </Text>
              </Stack>
              <Text>
                {health?.caddy === true || health?.caddy === "healthy"
                  ? "Веб-сервер доступен"
                  : health?.caddy === false || health?.caddy === "error"
                    ? "Веб-сервер недоступен"
                    : "Состояние веб-сервера неизвестно"}
              </Text>
              {health?.error && <ErrorMessage>{health.error}</ErrorMessage>}
              {certificate?.configured && (
                <Text tone="secondary">
                  Сертификат{" "}
                  {certificate.domain || health?.panelDomain || "панели"}:{" "}
                  {certificate.state === "pending"
                    ? "ожидается выдача"
                    : certificate.state === "issued"
                      ? "выдан"
                      : certificate.state}
                  {certificate.error ? `. ${certificate.error}` : ""}
                </Text>
              )}
              {certificate?.dnsState && (
                <Text tone="secondary">
                  Системный резолвер, включая hosts:{" "}
                  {certificate.addresses?.join(", ") ||
                    certificate.dnsError ||
                    "нет адресов"}
                </Text>
              )}
              {certificate?.tlsState && (
                <Text tone="secondary">
                  HTTPS на сервере —{" "}
                  {certificate.tlsState === "bootstrap"
                    ? "локальный сертификат"
                    : certificate.tlsState === "served"
                      ? "доверенный сертификат"
                      : certificate.tlsState === "cloudflare_origin"
                        ? "Cloudflare Origin CA для Full (strict)"
                        : certificate.tlsState}
                  {certificate.tlsError ? `. ${certificate.tlsError}` : ""}
                </Text>
              )}
              {panelAutomation?.dnsMode && (
                <Text>
                  Cloudflare:{" "}
                  {panelAutomation.dnsMode === "proxied" ? "Proxied" : "DNS Only"}
                  {panelAutomation.sslSelection === "automatic" &&
                    " · Automatic SSL/TLS"}
                  {cloudflareSSLLabel && ` · режим зоны: ${cloudflareSSLLabel}`}
                </Text>
              )}
              {panelAutomation?.detail && (
                <Text tone="secondary">{panelAutomation.detail}</Text>
              )}
              {!panelAutomation?.dnsMode && panelDomainSettings?.proxyWarning && (
                <ErrorMessage>{panelDomainSettings.proxyWarning}</ErrorMessage>
              )}
              <Stack direction="row" gap={3}>
                {!converged && health && (
                  <Button
                    loading={pending}
                    onPress={() => void mutate(() => api.reconcile())}
                  >
                    Применить повторно
                  </Button>
                )}
                <Button
                  variant="simple"
                  loading={refreshing}
                  onPress={() => void refresh(true)}
                >
                  Обновить состояние
                </Button>
              </Stack>
              <Text as="h2" size="xl">
                Маршрутизация
              </Text>
              <Text>
                HTTP/HTTPS: {config.httpRoutes.length} · TCP/UDP:{" "}
                {config.directRules.length}
              </Text>
              <Text tone="secondary">
                Сохранение изменений не означает их успешного применения.
              </Text>
            </Stack>
          </Card>
        )}
        {page === "settings" && (
          <Card>
            <Stack gap={1}>
              <DrawerButton
                label="Защита от DDoS"
                secondaryText="Политики защиты и состояние фильтрации"
                secondaryPlacement="below"
                icon="shield"
                onPress={() => navigate("settings/anti-ddos")}
              />
              <DrawerButton
                label="Cloudflare DNS"
                secondaryText="Подключение аккаунта и записи доменов"
                secondaryPlacement="below"
                icon="link"
                onPress={() => navigate("settings/cloudflare")}
              />
              <DrawerButton
                label="Доступ к панели"
                secondaryText="Сессия администратора"
                secondaryPlacement="below"
                icon="shield"
                onPress={() => navigate("settings/account")}
              />
            </Stack>
          </Card>
        )}
        {page === "settings/anti-ddos" && (
          <AntiDDoSPage
            config={config}
            onSaved={(next) => {
              if (renderEpoch === epoch.current && authenticated.current)
                setConfig((current) =>
                  current && current.revision > next.revision ? current : next,
                );
            }}
          />
        )}
        {page === "settings/cloudflare" && (
          <Card>
            <Cloudflare
              routes={config.httpRoutes}
              callback={cloudflareCallback}
            />
          </Card>
        )}
        {page === "settings/account" && (
          <Card>
            <Stack gap={4}>
              <Text>Вы вошли как администратор.</Text>
              <Button
                variant="simple"
                loading={pending}
                onPress={() => void logout()}
              >
                Выйти
              </Button>
            </Stack>
          </Card>
        )}
      </Page>
    </AppShell>
  );
}
const root = createRoot(document.getElementById("root")!);
const dispose = installControlMotion();
root.render(<App />);
if (import.meta.hot)
  import.meta.hot.dispose(() => {
    root.unmount();
    dispose();
  });
