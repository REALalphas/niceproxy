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
  e instanceof Error ? e.message : "Failed to complete action.";
const trafficStages = {
  pre_filter: "Pre-filter",
  accepted: "Accepted",
  routed: "Routed",
  forwarded: "Forwarded to backend",
  dropped: "Dropped",
  backend_rejected: "Rejected by backend",
};

const metricLabels: Record<string, string> = {
  ...trafficStages,
  active: "Active processing",
  tcp_new: "New TCP connections",
  tcp_active: "Active TCP connections",
  tcp_bytes: "TCP traffic volume",
  tls_new: "New TLS connections",
  tls_active: "Active TLS connections",
  tls_sessions: "TLS sessions",
  first_byte_ms: "Time to first byte, ms",
  header_ms: "Time to headers, ms",
  idle_ms: "Idle time, ms",
  udp_packets: "UDP packets",
  udp_bytes: "UDP traffic volume",
  udp_datagram_bytes: "UDP datagram size",
  cpu_percent: "CPU usage, %",
  memory_bytes: "Memory usage, bytes",
  backlog: "Incoming connection backlog",
  queue: "Queue depth",
  http_requests: "HTTP requests",
  http_active: "Active HTTP requests",
  http_connection_active: "Active HTTP connections",
  header_bytes: "Header size, bytes",
  body_bytes: "Request body size, bytes",
  response_ms: "Response time, ms",
  backend_active: "Active backend connections",
  backend_tcp_new: "New backend TCP connections",
  backend_tcp_bytes: "Backend TCP traffic, bytes",
  backend_udp_packets: "Backend UDP packets",
  backend_udp_bytes: "Backend UDP traffic, bytes",
  backend_response_ms: "Backend response time, ms",
};
const signalLabels: Record<(typeof signals)[number], string> = {
  tcp_new: metricLabels.tcp_new,
  tls_new: metricLabels.tls_new,
  requests: "Requests",
  udp_packets: metricLabels.udp_packets,
  udp_bytes: metricLabels.udp_bytes,
  protocol_errors: "Protocol errors",
  timeouts: "Timeouts",
  short_connections: "Short connections",
  backend_errors: "Backend errors",
  backend_latency_ms: "Backend latency, ms",
  pressure: "Resource pressure",
  distinct_sources: "Distinct sources",
  distinct_subnets: "Distinct subnets",
  kernel_drops: "Kernel-dropped packets",
  udp_unanswered: "Unanswered UDP requests",
};
const scopeLabels: Record<(typeof scopes)[number], string> = {
  ip: "IP address",
  subnet: "Subnet",
  listener: "Listener",
  endpoint: "Route",
  group: "Group",
  all_instances: "All instances",
};
const actionLabels: Record<(typeof actions)[number], string> = {
  pass: "Pass",
  slow: "Slow",
  reject: "Reject",
  block: "Block",
};
const unitLabels: Record<(typeof units)[number], string> = {
  count: "Count",
  bytes: "Bytes",
  ms: "Milliseconds",
  percent: "Percent",
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
  { key: "id", label: "Limit ID" },
  { key: "value", label: "Value" },
  { key: "unit", label: "Unit", choices: unitLabels },
  { key: "windowSeconds", label: "Limit window, s", optional: true },
  { key: "burst", label: "Allowed burst", optional: true },
  { key: "scope", label: "Scope", choices: scopeLabels },
  { key: "action", label: "Action on exceed", choices: actionLabels },
  { key: "ttlSeconds", label: "TTL, s", optional: true },
];
const ruleFields: Field[] = [
  { key: "id", label: "Rule ID" },
  { key: "signal", label: "Detector signal", choices: signalLabels },
  { key: "scope", label: "Scope", choices: scopeLabels },
  { key: "threshold", label: "Trigger threshold" },
  { key: "clearThreshold", label: "Clear threshold" },
  { key: "windowSeconds", label: "Observation window, s" },
  { key: "burst", label: "Allowed burst" },
  { key: "minSamples", label: "Minimum samples" },
  { key: "action", label: "Action on trigger", choices: actionLabels },
  { key: "cooldownSeconds", label: "Cooldown after trigger, s" },
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
    throw new Error(`Enter a non-negative number in "${label}".`);
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
        if (!value) throw new Error(`Fill in "${label}".`);
        return [
          [key, numericFields.has(key) ? numberField(value, label) : value],
        ];
      }),
    );
    const id = String(result.id);
    if (!policyId.test(id))
      throw new Error(
        "ID must contain 1 to 64 Latin letters, digits, dots, hyphens, or underscores.",
      );
    if (ids.has(id)) throw new Error(`Duplicate ID "${id}".`);
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
              Remove entry {index + 1}
            </Button>
          </Stack>
        </Card>
      ))}
      <Button
        disabled={disabled}
        onPress={() => onChange([...rows, newPolicyRow(defaults)])}
      >
        Add entry
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
    { key: "metric", label: "Limit metric", choices: metricChoices },
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
          ? numberField(stableWindows.trim(), "Stable windows")
          : undefined,
        limits: readPolicyRows(limits, fields),
        rules: readPolicyRows(rules, ruleFields),
      };
      if (!validPolicy(next))
        throw new Error(
          "Check parameters. Windows, durations, and sample counts must be integers.",
        );
      if (next.stableWindows !== undefined && next.stableWindows > 60)
        throw new Error("Specify at most 60 stable windows.");
      if (next.group && !policyId.test(next.group))
        throw new Error(
          "Group must contain 1 to 64 Latin letters, digits, dots, hyphens, or underscores.",
        );
      const ids = [...next.limits, ...next.rules].map(({ id }) => id);
      if (new Set(ids).size !== ids.length)
        throw new Error(
          "Limits and rules must have unique IDs.",
        );
      for (const limit of next.limits) {
        if (limit.value <= 0 || limit.unit !== metricUnit(limit.metric))
          throw new Error(
            `Check the value and unit of limit "${limit.id}".`,
          );
        if (rateMetrics.has(limit.metric)) {
          if (!limit.windowSeconds || limit.windowSeconds > 300)
            throw new Error(
              `For limit "${limit.id}", specify a window from 1 to 300 seconds.`,
            );
        } else if (limit.windowSeconds || limit.burst) {
          throw new Error(
            `For limit "${limit.id}", window and burst are only available for rate metrics.`,
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
            `Check window, minimum samples, and cooldown for rule "${rule.id}".`,
          );
        if (rule.clearThreshold >= rule.threshold)
          throw new Error(
            `For rule "${rule.id}", clear threshold must be less than trigger threshold.`,
          );
      }
      setBusy(true);
      await onSave(next);
      setMessage(
        "Settings saved. Apply status is shown in the summary.",
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
        <Text as="h2">{route ? "Route protection" : "Listener protection"}</Text>
        <div className="ddos-form-section">
          <Text as="h3">Protection mode</Text>
          <div className="ddos-policy-switches">
            {(
              [
                ["detect", "Attack detection"],
                ["autoFilter", "Automatic filtering"],
                ["enforceLimits", "Enforce limits"],
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
          <Text as="h3">Scope settings</Text>
          <div className="ddos-form-grid">
            <TextInput
              id={`${formId}-stable`}
              label="Stable windows"
              value={stableWindows}
              onValueChange={setStableWindows}
              disabled={busy}
            />
            <TextInput
              id={`${formId}-group`}
              label="Protection group"
              value={policy.group ?? ""}
              onValueChange={(group) => setPolicy({ ...policy, group })}
              disabled={busy}
            />
          </div>
        </div>
        {hasTLS && (
          <div className="ddos-form-section">
            <Text as="h3">Cloudflare trust</Text>
            <Switch
              id={`${formId}-cloudflare-only`}
              label="Allow traffic only from Cloudflare"
              checked={policy.cloudflareOnly ?? false}
              disabled={busy}
              onCheckedChange={(cloudflareOnly) =>
                setPolicy({ ...policy, cloudflareOnly })
              }
            />
            <TextArea
              id={`${formId}-origin-ca`}
              label="Origin Pull CA certificate (PEM)"
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
              label="Expect UDP response"
              checked={policy.expectUDPResponse ?? false}
              disabled={busy}
              onCheckedChange={(expectUDPResponse) => setPolicy({ ...policy, expectUDPResponse })}
            />
          </div>
        )}
        <PolicyRows
          heading="Limits"
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
          heading="Detector rules"
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
          Save policy
        </Button>
      </Stack>
    </form>
  );
}

const applyLabels = {
  active: "Applied",
  applying: "Applying",
  partial: "Partially applied",
};
const detectorLabels: Record<string, string> = {
  disabled: "Disabled",
  off: "Disabled",
  learning: "Learning",
  collecting: "Collecting data",
  partial: "Partial traffic visibility",
  warming_up: "Collecting baseline data",
  normal: "Normal",
  stable: "Normal",
  suspect: "Suspected attack",
  suspected: "Suspected attack",
  suspicious: "Suspected attack",
  attack: "Attack detected",
  mitigation: "Filtering traffic",
  mitigating: "Filtering traffic",
  cooldown: "Post-trigger cooldown",
  recovering: "Recovering",
  unavailable: "No data",
};
const observationLabels: Record<string, string> = {
  full: "Full",
  socket: "Socket-level observation",
  partial: "Partial",
  unavailable: "No data",
  none: "No data",
};
const detectorReasons: Record<string, string> = {
  detector_disabled: "Detector disabled",
  warming_up: "Collecting baseline data",
  pre_filter_incomplete: "Only partial pre-filter data available",
  corroborated_rule: "Rule trigger corroborated",
  input_and_backend_stable: "Incoming traffic and backend are stable",
  stable_windows_required: "Waiting for stable observation windows",
  anomalies_or_resource_pressure: "Traffic anomalies or high resource pressure",
  resource_or_backend_observation_missing: "Resource or backend observation data missing",
};
const translated = (labels: Record<string, string>, key: string) =>
  Object.hasOwn(labels, key) ? labels[key] : key;
const displayNumber = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 3,
});
const formatMetric = (value: number | null | undefined) =>
  value == null ? "no data" : displayNumber.format(value);
const displayTime = (value: string) => new Date(value).toLocaleString("en-US");

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
  const statusLabel = status ? applyLabels[status.status] : "No data";
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
                <Text as="h2">Protection status</Text>
                <Text tone="secondary">
                  Configuration rollout and instance observability
                </Text>
              </Stack>
            </div>
            <Badge value={statusLabel} />
            <Button onPress={onRefresh} disabled={busy}>
              Refresh summary
            </Button>
          </div>
          <div className="ddos-summary-grid">
            <StatusItem label="Desired revision">
              {status ? status.revision : "no data"}
            </StatusItem>
            <StatusItem label="Applied revision">
              {status ? status.appliedRevision : "no data"}
            </StatusItem>
            <StatusItem label="Instances">
              {status ? status.instances.length : "no data"}
            </StatusItem>
          </div>
          {error && <ErrorMessage>{error}</ErrorMessage>}
          {!status && !error && <Text tone="muted">Apply status — no data</Text>}
          {status && !hasTargets && (
            <Card>
              <Stack gap={2}>
                <Text as="h3">No active observation targets</Text>
                <div className="ddos-empty">
                  <Text tone="secondary">
                    Metrics will appear after configuring a listener or route.
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
                <Text as="h2">Instance {instance.id}</Text>
                <Text tone="secondary">Version {instance.version}</Text>
              </Stack>
              {instance.error && <Badge value="Instance error" />}
            </div>
            {instance.error && <ErrorMessage>{instance.error}</ErrorMessage>}
            {instance.cloudflare && (
              <Card>
                <Stack gap={3}>
                  <Stack gap={1}>
                    <Text as="h3">Cloudflare networks</Text>
                    <Text tone="secondary">Trusted addresses for source filtering</Text>
                  </Stack>
                  <div className="ddos-summary-grid">
                    <StatusItem label="Network count">
                      {formatMetric(
                        typeof instance.cloudflare.networks === "number"
                          ? instance.cloudflare.networks
                          : instance.cloudflare.networks?.length,
                      )}
                    </StatusItem>
                    <StatusItem label="Updated">
                      {instance.cloudflare.updatedAt
                        ? displayTime(instance.cloudflare.updatedAt)
                        : "no data"}
                    </StatusItem>
                    <StatusItem label="Source">
                      {instance.cloudflare.ipv4URL || instance.cloudflare.ipv6URL || "not configured"}
                    </StatusItem>
                  </div>
                  {instance.cloudflare.error && <ErrorMessage>{instance.cloudflare.error}</ErrorMessage>}
                </Stack>
              </Card>
            )}
            {!instance.targets.length && <Text tone="muted">Observation targets — no data</Text>}
            <div className="ddos-target-list">
              {instance.targets.map((target) => (
                <Card key={target.id}>
                  <Stack gap={4}>
                    <div className="ddos-target-heading">
                      <Stack gap={1}>
                        <Text as="h2">{target.label || target.id}</Text>
                        <Text tone="secondary">Target {target.id}</Text>
                      </Stack>
                      <Badge value={translated(detectorLabels, target.state)} />
                    </div>
                    <div className="ddos-target-summary">
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Detector score</Text>
                        <Text font="mono">{formatMetric(target.score)}</Text>
                      </div>
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Reason</Text>
                        <Text>{target.reason ? translated(detectorReasons, target.reason) : "no data"}</Text>
                      </div>
                      <div className="ddos-target-summary-item">
                        <Text tone="muted">Observability</Text>
                        <Text>{translated(observationLabels, target.observability)}</Text>
                      </div>
                    </div>
                    <Card>
                      <Stack gap={2}>
                        <Text as="h3">Applied policy</Text>
                        <Text>
                          Detection {target.policy.detect ? "enabled" : "disabled"} · auto-filtering {target.policy.autoFilter ? "enabled" : "disabled"} · limits {target.policy.enforceLimits ? "enabled" : "disabled"}
                        </Text>
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Processing stages and metrics</Text>
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
                                  <Text tone="muted">{metric?.source ? `Source: ${metric.source}` : "Source not specified"}</Text>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Active limits</Text>
                        {!target.policy.enforceLimits ? (
                          <Text tone="muted">Limit enforcement disabled</Text>
                        ) : target.policy.limits?.length ? (
                          <div className="ddos-detail-list">
                            {target.policy.limits.map((limit) => (
                              <DetailRow key={limit.id} label={limit.id}>
                                {translated(metricLabels, limit.metric)} · {formatMetric(limit.value)} {unitLabels[limit.unit]} · {scopeLabels[limit.scope]} · {actionLabels[limit.action]}{limit.windowSeconds !== undefined ? ` · window ${limit.windowSeconds} s` : ""}
                              </DetailRow>
                            ))}
                          </div>
                        ) : (
                          <Text tone="muted">No limits configured</Text>
                        )}
                      </Stack>
                    </Card>
                    <Card>
                      <Stack gap={3}>
                        <Text as="h3">Active restrictions</Text>
                        {!target.restrictions?.length && <Text tone="muted">No restrictions</Text>}
                        {target.restrictions?.map((restriction, index) => (
                          <Stack key={index} gap={2}>
                            <DetailRow label={`${actionLabels[restriction.action]} · ${scopeLabels[restriction.scope]}`}>
                              {restriction.target} · rule {restriction.rule} · until {displayTime(restriction.expiresAt)} · {restriction.automatic ? "automatic" : "manual"}
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
                                Clear restriction for 60 seconds
                              </Button>
                            )}
                          </Stack>
                        ))}
                      </Stack>
                    </Card>
                    {!!target.events?.length && (
                      <Card>
                        <Stack gap={3}>
                          <Text as="h3">Detector events</Text>
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
                          <Text as="h3">Load history</Text>
                          <div className="ddos-detail-list">
                            {target.history.map((point, index) => (
                              <DetailRow key={index} label={displayTime(point.at)}>
                                {formatMetric(point.load)} · normal {formatMetric(point.normalLow)}–{formatMetric(point.normalHigh)}
                              </DetailRow>
                            ))}
                          </div>
                        </Stack>
                      </Card>
                    )}
                    {!!target.sources?.length && (
                      <Card>
                        <Stack gap={3}>
                          <Text as="h3">Traffic sources</Text>
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
            "Settings saved. Apply status is shown in the summary.",
          );
        } catch (e) {
          setError(err(e));
        } finally {
          setBusy(false);
        }
      }}
    >
      <Stack gap={3}>
        <Text as="h2">Trusted Cloudflare networks</Text>
        <Switch
          id="ddos-cf"
          label="Enable trust for Cloudflare networks"
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-ipv4"
          type="url"
          label="IPv4 network list URL"
          value={ipv4URL}
          onValueChange={setIPv4}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-ipv6"
          type="url"
          label="IPv6 network list URL"
          value={ipv6URL}
          onValueChange={setIPv6}
          disabled={busy}
        />
        <TextInput
          id="ddos-cf-proxies"
          label="Trusted proxies (comma-separated)"
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
          Save Cloudflare networks
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
                  label="Protection scope"
                  value={selected}
                  onValueChange={setEditor}
                  popup="overlay"
                  options={[
                    { value: "listener", label: "Global listener" },
                    { value: "cloudflare", label: "Trusted Cloudflare networks" },
                    ...routes.map((item) => ({
                      value: `route:${item.id}`,
                      label: `Route · ${source(item)}`,
                    })),
                  ]}
                />
              </div>
              <Button
                variant="blank"
                onPress={() => setEditorVersion((current) => current + 1)}
              >
                Reset changes
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
                    ? "Sign in to Niceproxy"
                    : "Initial setup"}
                </Text>
                <Text tone="secondary">
                  {initial.configured
                    ? "Enter administrator password."
                    : "Create an administrator password: 12 to 72 bytes."}
                </Text>
                <TextInput
                  showIcon
                  id="password"
                  label="Password"
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
                  {initial.configured ? "Sign in" : "Save password"}
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
    ? "Disabled"
    : route.status === "healthy"
      ? "Applied"
      : route.status === "waiting_acme"
        ? "Waiting for certificate"
        : route.status === "waiting_dns"
          ? "Waiting for DNS"
          : route.status === "invalid_certificate"
            ? "Invalid certificate"
            : route.status === "error"
              ? "Apply error"
              : "Unconfirmed";
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
  if (!settings) return ["Public ports are configured automatically"];
  const label = (owner: PortOwners[keyof PortOwners]) =>
    owner === "direct" ? "Direct forwarding" : "Web access";
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
              <Text>{error || "Connecting to service…"}</Text>
              {error && (
                <Button onPress={() => void initialize()}>Retry</Button>
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
      ? "Service"
      : page === "settings/anti-ddos"
        ? "DDoS protection"
        : page === "settings/cloudflare"
            ? "Cloudflare DNS"
            : page === "settings/account"
              ? "Panel access"
              : page === "settings"
                ? "Settings"
                : isList
                  ? "Routes"
                  : isCreating
                    ? page.endsWith("/http")
                      ? "New HTTP/HTTPS route"
                      : page.endsWith("/direct") ||
                          page.endsWith("/tcp") ||
                          page.endsWith("/udp")
                        ? "New TCP/UDP rule"
                        : "New route"
                    : mode === "edit"
                      ? "Edit route"
                      : mode === "delete"
                        ? "Delete route"
                        : "Route";
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
      accountLabel="Administrator account"
      items={[
        { id: "routes", label: "Routes", icon: "link" },
        { id: "overview", label: "Service", icon: "device" },
        { id: "settings", label: "Settings", icon: "settings" },
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
              Back
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
                Add route
              </Button>
              <IconButton
                icon="refresh"
                label="Refresh routes"
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
                label="Protocol"
                variant="plain"
                value={filter}
                onValueChange={setFilter}
                options={[
                  { value: "all", label: "All protocols" },
                  { value: "http", label: "HTTP/HTTPS" },
                  { value: "tcp", label: "TCP" },
                  { value: "udp", label: "UDP" },
                ]}
              />
              <Text tone="muted">
                {visible.length} of {mappings.length}
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
                        <Text tone="muted">Service</Text>
                        <Text font="mono">{target(route)}</Text>
                      </Stack>
                      <Button
                        variant="simple"
                        onPress={() => navigate(`routes/view/${key}`)}
                      >
                        Open route
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
                      ? "No routes of this type"
                      : "Connect your first service"}
                  </Text>
                  <Text tone="secondary">
                    {mappings.length
                      ? "Select another protocol or add a route."
                      : "HTTP/HTTPS — by domain and path. TCP/UDP — by port."}
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
              <Text>Route not found.</Text>
              <Button onPress={() => navigate("routes")}>Back to routes</Button>
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
                  Delete route? New connections will stop being served.
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
                    Delete route
                  </Button>
                  <Button
                    variant="blank"
                    disabled={pending}
                    onPress={() => navigate(`routes/view/${mapping.key}`)}
                  >
                    Cancel
                  </Button>
                </Stack>
              </Stack>
            ) : (
              <Stack gap={5}>
                <Stack gap={1}>
                  <Text tone="secondary">Incoming address</Text>
                  <Text font="mono" size="lg">
                    {source(mapping.route)}
                  </Text>
                </Stack>
                {publicPortLines(mapping.route, owners).length > 0 && (
                  <Stack gap={1}>
                    <Text tone="secondary">Public ports</Text>
                    {publicPortLines(mapping.route, owners).map((line) => (
                      <Text key={line} font="mono">
                        {line}
                      </Text>
                    ))}
                  </Stack>
                )}
                <Stack gap={1}>
                  <Text tone="secondary">Service</Text>
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
                      ? "Automatic TLS"
                      : mapping.route.tls === "internal"
                        ? "Internal certificate"
                        : "No TLS"}{" "}
                    ·{" "}
                    {mapping.route.stripPrefix
                      ? "Path prefix stripped"
                      : "Path preserved"}
                  </Text>
                ) : (
                  <Text tone="secondary">
                    {mapping.route.stats
                      ? `Active ${mapping.route.stats.active} · total ${mapping.route.stats.accepted} · errors ${mapping.route.stats.errors} · rejected ${mapping.route.stats.rejects}. ${mapping.route.protocol === "udp" ? "UDP sessions" : "TCP connections"} since process start.`
                      : "Statistics unavailable"}
                  </Text>
                )}
                {!systemRoute && (
                  <Switch
                    id="route-enabled"
                    label="Route enabled"
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
                    The system panel route is managed by the panel domain
                    setting.
                  </Text>
                )}
                <Stack direction="row" gap={3}>
                  {!systemRoute && (
                    <Button
                      variant="simple"
                      onPress={() => navigate(`routes/edit/${mapping.key}`)}
                    >
                      Edit
                    </Button>
                  )}
                  <Button
                    variant="blank"
                    onPress={() => void refresh(true)}
                    loading={refreshing}
                  >
                    Refresh
                  </Button>
                  {!systemRoute && (
                    <Button
                      variant="blank"
                      onPress={() => navigate(`routes/delete/${mapping.key}`)}
                    >
                      Delete
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
                    ? "Status unavailable"
                    : health.state === "invalid_certificate" && converged
                      ? "Invalid panel certificate"
                      : health.state === "waiting_acme" && converged
                        ? "Waiting for public certificate"
                        : applied
                          ? "Configuration applied"
                          : health.status === "error"
                            ? "Apply error"
                            : "Configuration partially applied"}
                </Text>
                <Text tone="secondary">
                  Saved:{" "}
                  <Text as="span" font="mono">
                    {config.revision}
                  </Text>{" "}
                  · applied:{" "}
                  <Text as="span" font="mono">
                    {health
                      ? health.appliedRevision < 0
                        ? "partial"
                        : health.appliedRevision
                      : "unknown"}
                  </Text>
                </Text>
              </Stack>
              <Text>
                {health?.caddy === true || health?.caddy === "healthy"
                  ? "Web server available"
                  : health?.caddy === false || health?.caddy === "error"
                    ? "Web server unavailable"
                    : "Web server status unknown"}
              </Text>
              {health?.error && <ErrorMessage>{health.error}</ErrorMessage>}
              {certificate?.configured && (
                <Text tone="secondary">
                  Certificate{" "}
                  {certificate.domain || health?.panelDomain || "panel"}:{" "}
                  {certificate.state === "pending"
                    ? "pending issuance"
                    : certificate.state === "issued"
                      ? "issued"
                      : certificate.state}
                  {certificate.error ? `. ${certificate.error}` : ""}
                </Text>
              )}
              {certificate?.dnsState && (
                <Text tone="secondary">
                  System resolver, including hosts:{" "}
                  {certificate.addresses?.join(", ") ||
                    certificate.dnsError ||
                    "no addresses"}
                </Text>
              )}
              {certificate?.tlsState && (
                <Text tone="secondary">
                  Server HTTPS —{" "}
                  {certificate.tlsState === "bootstrap"
                    ? "local certificate"
                    : certificate.tlsState === "served"
                      ? "trusted certificate"
                      : certificate.tlsState === "cloudflare_origin"
                        ? "Cloudflare Origin CA for Full (strict)"
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
                  {cloudflareSSLLabel && ` · zone mode: ${cloudflareSSLLabel}`}
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
                    Reapply
                  </Button>
                )}
                <Button
                  variant="simple"
                  loading={refreshing}
                  onPress={() => void refresh(true)}
                >
                  Refresh status
                </Button>
              </Stack>
              <Text as="h2" size="xl">
                Routing
              </Text>
              <Text>
                HTTP/HTTPS: {config.httpRoutes.length} · TCP/UDP:{" "}
                {config.directRules.length}
              </Text>
              <Text tone="secondary">
                Saving changes does not mean they were successfully applied.
              </Text>
            </Stack>
          </Card>
        )}
        {page === "settings" && (
          <Card>
            <Stack gap={1}>
              <DrawerButton
                label="DDoS protection"
                secondaryText="Protection policies and filtering status"
                secondaryPlacement="below"
                icon="shield"
                onPress={() => navigate("settings/anti-ddos")}
              />
              <DrawerButton
                label="Cloudflare DNS"
                secondaryText="Account connection and domain records"
                secondaryPlacement="below"
                icon="link"
                onPress={() => navigate("settings/cloudflare")}
              />
              <DrawerButton
                label="Panel access"
                secondaryText="Administrator session"
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
              <Text>Signed in as administrator.</Text>
              <Button
                variant="simple"
                loading={pending}
                onPress={() => void logout()}
              >
                Sign out
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
