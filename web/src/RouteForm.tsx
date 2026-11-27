import { useState, type FormEvent, type ReactNode } from "react";
import {
  Button,
  Card,
  Icon,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@alpha/react";
import {
  api,
  type DirectRule,
  type HttpRoute,
  type PortOwnerSettings,
} from "./api";
import { formatEndpoint, isDirectIP, isDirectTarget } from "./direct-address";
import { validHttpPath } from "./http-path";
import "./route-form.css";

type Route = HttpRoute | DirectRule;
type Protocol = "http" | DirectRule["protocol"];
type DirectField = "listenHost" | "listenPort" | "targetHost" | "targetPort";
type DirectErrors = Partial<Record<DirectField, string>>;

const directProtocols = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
];
const protocols = [{ value: "http", label: "HTTP/HTTPS" }, ...directProtocols];

const validPort = (value: string) =>
  /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;

function httpTargetError(value: string): string | undefined {
  // Caddy accepts DNS names such as app.123 that the browser URL parser rejects.
  const match =
    /^(https?|tcp|udp):\/\/(\[[^\]]+\]|[^:/?#@\\\[\]\s]+)(?::(\d*))?\/?#?$/i.exec(value);
  if (!match || !isDirectTarget(match[2].replace(/^\[|\]$/g, "")))
    return "Enter an HTTP(S), TCP, or UDP service address without path, query parameters, or password.";
  if ((match[1] === "tcp" || match[1] === "udp") && !match[3])
    return "Specify a service port for TCP/UDP.";
  if (match[3] !== undefined && !validPort(match[3]))
    return "Specify a service port from 1 to 65535.";
}

function RouteFlow({
  incoming,
  ports,
  rules,
  upstream,
}: {
  incoming: string;
  ports: string[];
  rules: string;
  upstream: string;
}) {
  const steps = [
    {
      icon: "link",
      label: "Connection",
      detail: incoming || "Enter incoming address",
      mono: !!incoming,
    },
    {
      icon: "device",
      label: "Public ports",
      detail: ports,
      mono: false,
    },
    { icon: "shield", label: "Rules", detail: rules, mono: false },
    {
      icon: "device",
      label: "Service",
      detail: upstream || "Enter service address",
      mono: !!upstream,
    },
  ] as const;
  return (
    <Card>
      <div className="route-flow-container">
        <ol className="route-flow" role="list" aria-label="Route flow">
          {steps.map((step, index) => (
            <li className="route-flow-step" key={step.label}>
              <Icon name={step.icon} />
              <Text font="heading" weight="bold">
                {step.label}
              </Text>
              <div className="route-flow-detail">
                {Array.isArray(step.detail) ? (
                  <Stack gap={1}>
                    {step.detail.map((line) => (
                      <Text key={line} font="mono" tone="secondary">
                        {line}
                      </Text>
                    ))}
                  </Stack>
                ) : (
                  <Text font={step.mono ? "mono" : "ui"} tone="secondary">
                    {step.detail}
                  </Text>
                )}
              </div>
              {index < steps.length - 1 && (
                <span className="route-flow-arrow" aria-hidden="true">
                  ↓
                </span>
              )}
            </li>
          ))}
        </ol>
      </div>
    </Card>
  );
}

function RouteSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section aria-label={title}>
      <Stack gap={3}>
        <Text as="h2" size="xl">
          {title}
        </Text>
        {children}
      </Stack>
    </section>
  );
}

export function RouteForm({
  route,
  ports,
  initialProtocol = "http",
  onDone,
  onCancel,
}: {
  route?: Route;
  ports?: PortOwnerSettings | null;
  initialProtocol?: Protocol;
  onDone: (route: Route) => void;
  onCancel: () => void;
}) {
  const httpRoute = route && "host" in route ? route : undefined;
  const directRule = route && "protocol" in route ? route : undefined;
  const [protocol, setProtocol] = useState<Protocol>(
    httpRoute ? "http" : (directRule?.protocol ?? initialProtocol),
  );
  const [host, setHost] = useState(httpRoute?.host ?? "");
  const [path, setPath] = useState(
    httpRoute?.path === "/" ? "" : (httpRoute?.path ?? ""),
  );
  const [tls, setTls] = useState(httpRoute?.tls ?? "auto");
  const [httpTarget, setHttpTarget] = useState(httpRoute?.target ?? "");
  const [stripPrefix, setStripPrefix] = useState(!!httpRoute?.stripPrefix);
  const [listenHost, setListenHost] = useState(
    directRule?.listenHost === "0.0.0.0" ? "" : (directRule?.listenHost ?? ""),
  );
  const [listenPort, setListenPort] = useState(
    String(directRule?.listenPort ?? ""),
  );
  const [targetHost, setTargetHost] = useState(directRule?.targetHost ?? "");
  const [targetPort, setTargetPort] = useState(
    String(directRule?.targetPort ?? ""),
  );
  const [enabled, setEnabled] = useState(route?.enabled ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<DirectErrors>({});

  const isHttp = protocol === "http";
  const pathValid = validHttpPath(path);
  const effectivePath = path.replace(/\/$/, "") || "/";
  const canStripPrefix = pathValid && effectivePath !== "/";
  const strip = canStripPrefix && stripPrefix;
  const effectiveListenHost = listenHost.trim() || "0.0.0.0";
  const effectiveTargetPort = targetPort || listenPort;
  const trimmedTargetHost = targetHost.trim();
  const httpHost = host.trim().toLowerCase();
  const httpOrigin = httpTarget.trim();
  const originError = isHttp ? httpTargetError(httpOrigin) : undefined;
  const httpProtocol = tls === "off" ? "HTTP" : "HTTPS";
  const incoming = isHttp
    ? isDirectTarget(httpHost) && !isDirectIP(httpHost) && pathValid
      ? `${httpProtocol} · ${httpHost}${effectivePath}`
      : ""
    : isDirectIP(effectiveListenHost)
      ? `${protocol.toUpperCase()} ${formatEndpoint(effectiveListenHost, validPort(listenPort) ? Number(listenPort) : "…")}`
      : "";
  const upstream = isHttp
    ? originError
      ? ""
      : httpOrigin.replace(/\/?#?$/, "") +
        (pathValid && !strip ? effectivePath : "/")
    : isDirectTarget(trimmedTargetHost)
      ? `${protocol.toUpperCase()} ${formatEndpoint(trimmedTargetHost, validPort(effectiveTargetPort) ? Number(effectiveTargetPort) : "…")}`
      : "";
  const rules = !enabled
    ? "Route disabled"
    : isHttp
      ? "Match by domain and path"
      : "Direct forwarding";
  const publicPorts = isHttp
    ? ports
      ? tls === "off"
        ? [
            `HTTP · TCP ${ports.httpPort} → ${
              ports.owners.http === "direct"
                ? "used by direct forwarding"
                : "web access"
            }`,
          ]
        : [
            `HTTPS · TCP ${ports.httpsPort} → ${
              ports.owners.https === "direct"
                ? "used by direct forwarding"
                : "web access"
            }`,
            `HTTP/3 · UDP ${ports.httpsPort} → ${
              ports.owners.http3 === "direct"
                ? "used by direct forwarding"
                : "web access"
            }`,
          ]
      : ["Public ports will be selected automatically"]
    : [
        `${protocol.toUpperCase()} ${
          validPort(listenPort)
            ? formatEndpoint(effectiveListenHost, Number(listenPort))
            : "incoming port"
        } → direct forwarding`,
      ];

  function clearFieldError(field: DirectField) {
    setFieldErrors((current) => ({ ...current, [field]: undefined }));
    setError("");
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    try {
      if (protocol === "http") {
        if (originError) throw new Error(originError);
        if (!httpHost) throw new Error("Enter a domain.");
        if (!pathValid)
          throw new Error(
            "Enter a literal path starting with / without spaces, control characters, //, . or .., parameters, or wildcards (up to 2048 bytes).",
          );
        setBusy(true);
        onDone(
          await api.saveHttp(
            {
              host: host.trim(),
              path: effectivePath,
              stripPrefix: strip,
              target: httpOrigin,
              tls,
              enabled,
            },
            httpRoute?.id,
          ),
        );
        return;
      }
      const errors: DirectErrors = {};
      if (!isDirectIP(effectiveListenHost))
        errors.listenHost = "Enter an interface IP or leave empty.";
      if (!validPort(listenPort))
        errors.listenPort = "Enter an incoming port from 1 to 65535.";
      if (!trimmedTargetHost)
        errors.targetHost = "Enter a service IP address or domain.";
      else if (!isDirectTarget(trimmedTargetHost))
        errors.targetHost =
          "Enter an IP address or domain without scheme, path, or port.";
      if (targetPort && !validPort(targetPort))
        errors.targetPort =
          "Enter a port from 1 to 65535 or leave empty.";
      setFieldErrors(errors);
      if (Object.keys(errors).length) return;
      setBusy(true);
      onDone(
        await api.saveDirect(
          {
            protocol,
            listenHost: effectiveListenHost,
            listenPort: Number(listenPort),
            targetHost: trimmedTargetHost,
            targetPort: Number(effectiveTargetPort),
            enabled,
          },
          directRule?.id,
        ),
      );
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to save route.",
      );
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <Stack gap={4}>
        <RouteFlow
          incoming={incoming}
          ports={publicPorts}
          rules={rules}
          upstream={upstream}
        />
        <Card>
          <Stack gap={5}>
            <RouteSection title="Connection point">
              {!httpRoute && (
                <Select
                  popup="overlay"
                  id="route-protocol"
                  label="Protocol"
                  value={protocol}
                  disabled={busy}
                  options={directRule ? directProtocols : protocols}
                  onValueChange={(value) => {
                    if (
                      value === "http" ||
                      value === "tcp" ||
                      value === "udp"
                    ) {
                      setProtocol(value);
                      setError("");
                    }
                  }}
                />
              )}
              {isHttp ? (
                <>
                  <div
                    role="group"
                    aria-label="Domain and path"
                    aria-describedby="http-path-example"
                  >
                    <Stack gap={2}>
                      <Stack
                        direction="row"
                        columns="wide-start"
                        align="start"
                        gap={3}
                      >
                        <TextInput
                          id="http-host"
                          label="Domain"
                          labelPlacement="above"
                          showIcon={false}
                          value={host}
                          onValueChange={(value) => {
                            setHost(value);
                            setError("");
                          }}
                          placeholder="example.com"
                          required
                          disabled={busy}
                        />
                        <TextInput
                          id="http-path"
                          label="Path"
                          labelPlacement="above"
                          showIcon={false}
                          value={path}
                          onValueChange={(value) => {
                            setPath(value);
                            setError("");
                            if (
                              !value ||
                              value === "/" ||
                              !validHttpPath(value)
                            )
                              setStripPrefix(false);
                          }}
                          placeholder="/"
                          disabled={busy}
                        />
                      </Stack>
                      <div id="http-path-example">
                        <Text tone="secondary">
                          For example, / matches all paths, while /api matches
                          /api and /api/users.
                        </Text>
                      </div>
                    </Stack>
                  </div>
                  <Select
                    popup="overlay"
                    id="tls"
                    label="HTTPS access"
                    value={tls}
                    onValueChange={(value) => {
                      if (
                        value === "auto" ||
                        value === "internal" ||
                        value === "off"
                      ) {
                        setTls(value);
                        setError("");
                      }
                    }}
                    hint="Use the same mode for all paths of the same domain."
                    disabled={busy}
                    options={[
                      { value: "auto", label: "Automatic certificate" },
                      {
                        value: "internal",
                        label: "Local certificate",
                      },
                      { value: "off", label: "No HTTPS (HTTP)" },
                    ]}
                  />
                </>
              ) : (
                <>
                  <Stack
                    direction="row"
                    columns="wide-start"
                    align="start"
                    gap={3}
                  >
                    <TextInput
                      id="listen-host"
                      label="Server IP"
                      labelPlacement="above"
                      showIcon={false}
                      value={listenHost}
                      onValueChange={(value) => {
                        setListenHost(value);
                        clearFieldError("listenHost");
                      }}
                      error={fieldErrors.listenHost}
                      placeholder="0.0.0.0"
                      disabled={busy}
                    />
                    <TextInput
                      id="listen-port"
                      label="Port"
                      labelPlacement="above"
                      showIcon={false}
                      type="tel"
                      value={listenPort}
                      onValueChange={(value) => {
                        setListenPort(value);
                        clearFieldError("listenPort");
                      }}
                      error={fieldErrors.listenPort}
                      disabled={busy}
                    />
                  </Stack>
                  <Text tone="secondary">
                    Leave IP empty to listen on all interfaces.
                  </Text>
                </>
              )}
            </RouteSection>
            <RouteSection title="Rules">
              <Switch
                id="route-form-enabled"
                label="Route enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={busy}
              />
              <Text tone="secondary">
                Access filters, DDoS protection, and login panel (Secured Route)
                are not available in route settings.
              </Text>
            </RouteSection>
            <RouteSection title="Proxying">
              {isHttp ? (
                <>
                  <TextInput
                    id="http-target"
                    label="Service URL"
                    labelPlacement="above"
                    showIcon={false}
                    value={httpTarget}
                    onValueChange={(value) => {
                      setHttpTarget(value);
                      setError("");
                    }}
                    placeholder="http://127.0.0.1:8080"
                    hint="Enter the service HTTP(S) address. You can omit the port if it is standard."
                    required
                    disabled={busy}
                  />
                  <Switch
                    id="http-strip-prefix"
                    label="Strip path prefix"
                    hint="For example, /api/users → /users. Query parameters are preserved."
                    checked={strip}
                    onCheckedChange={setStripPrefix}
                    disabled={busy || !canStripPrefix}
                  />
                </>
              ) : (
                <>
                  <Stack
                    direction="row"
                    columns="wide-start"
                    align="start"
                    gap={3}
                  >
                    <TextInput
                      id="target-host"
                      label="IP or domain"
                      labelPlacement="above"
                      showIcon={false}
                      value={targetHost}
                      onValueChange={(value) => {
                        setTargetHost(value);
                        clearFieldError("targetHost");
                      }}
                      error={fieldErrors.targetHost}
                      disabled={busy}
                    />
                    <TextInput
                      id="target-port"
                      label="Port"
                      labelPlacement="above"
                      showIcon={false}
                      type="tel"
                      value={targetPort}
                      onValueChange={(value) => {
                        setTargetPort(value);
                        clearFieldError("targetPort");
                      }}
                      error={fieldErrors.targetPort}
                      placeholder={
                        validPort(listenPort) ? listenPort : undefined
                      }
                      disabled={busy}
                    />
                  </Stack>
                  <Text tone="secondary">
                    If the service port is empty, the incoming port is used.
                  </Text>
                </>
              )}
            </RouteSection>
            {error && (
              <div role="alert">
                <Text>{error}</Text>
              </div>
            )}
            <Stack direction="row" gap={3}>
              <Button type="submit" loading={busy} disabled={busy}>
                {route ? "Save route" : "Create route"}
              </Button>
              <Button
                type="button"
                variant="blank"
                onPress={onCancel}
                disabled={busy}
              >
                Cancel
              </Button>
            </Stack>
          </Stack>
        </Card>
      </Stack>
    </form>
  );
}
