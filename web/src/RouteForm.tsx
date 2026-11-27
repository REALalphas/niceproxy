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
import { t, useI18n } from "./i18n";
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
    /^(https?|tcp|udp):\/\/(\[[^\]]+\]|[^:/?#@\\\[\]\s]+)(?::(\d*))?\/?#?$/i.exec(
      value,
    );
  if (!match || !isDirectTarget(match[2].replace(/^\[|\]$/g, "")))
    return t("routeErrors.targetAddress");
  if ((match[1] === "tcp" || match[1] === "udp") && !match[3])
    return t("routeErrors.targetPort");
  if (match[3] !== undefined && !validPort(match[3]))
    return t("errors.invalidPort");
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
  useI18n();
  const steps = [
    {
      icon: "link",
      label: t("route.connection"),
      detail: incoming || t("route.incomingHint"),
      mono: !!incoming,
    },
    {
      icon: "device",
      label: t("route.publicPorts"),
      detail: ports,
      mono: false,
    },
    { icon: "shield", label: t("route.rules"), detail: rules, mono: false },
    {
      icon: "device",
      label: t("routes.service"),
      detail: upstream || t("route.serviceHint"),
      mono: !!upstream,
    },
  ] as const;
  return (
    <Card>
      <div className="route-flow-container">
        <ol className="route-flow" role="list" aria-label={t("route.diagram")}>
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
    ? t("routes.status.disabled")
    : isHttp
      ? t("route.domainPathMatch")
      : t("route.directForward");
  const publicPorts = isHttp
    ? ports
      ? tls === "off"
        ? [
            `HTTP · TCP ${ports.httpPort} → ${
              ports.owners.http === "direct"
                ? t("route.directBusy")
                : t("route.webAccess")
            }`,
          ]
        : [
            `HTTPS · TCP ${ports.httpsPort} → ${
              ports.owners.https === "direct"
                ? t("route.directBusy")
                : t("route.webAccess")
            }`,
            `HTTP/3 · UDP ${ports.httpsPort} → ${
              ports.owners.http3 === "direct"
                ? t("route.directBusy")
                : t("route.webAccess")
            }`,
          ]
      : [t("route.publicPortsAuto")]
    : [
        `${protocol.toUpperCase()} ${
          validPort(listenPort)
            ? formatEndpoint(effectiveListenHost, Number(listenPort))
            : t("route.incomingPort")
        } → ${t("route.directForward")}`,
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
        if (!httpHost) throw new Error(t("routeErrors.domain"));
        if (!pathValid) throw new Error(t("routeErrors.path"));
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
        errors.listenHost = t("routeErrors.listenHost");
      if (!validPort(listenPort))
        errors.listenPort = t("routeErrors.listenPort");
      if (!trimmedTargetHost) errors.targetHost = t("routeErrors.targetHost");
      else if (!isDirectTarget(trimmedTargetHost))
        errors.targetHost = t("routeErrors.targetHostFormat");
      if (targetPort && !validPort(targetPort))
        errors.targetPort = t("routeErrors.targetPortOptional");
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
      setError(e instanceof Error ? e.message : t("errors.saveRoute"));
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
            <RouteSection title={t("route.connectionPoint")}>
              {!httpRoute && (
                <Select
                  popup="overlay"
                  id="route-protocol"
                  label={t("routes.protocol")}
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
                    aria-label={`${t("routes.domain")} ${t("routes.path")}`}
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
                          label={t("routes.domain")}
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
                          label={t("routes.path")}
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
                        <Text tone="secondary">{t("route.pathHint")}</Text>
                      </div>
                    </Stack>
                  </div>
                  <Select
                    popup="overlay"
                    id="tls"
                    label={t("route.httpsAccess")}
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
                    hint={t("route.tlsHint")}
                    disabled={busy}
                    options={[
                      { value: "auto", label: t("route.tlsAuto") },
                      {
                        value: "internal",
                        label: t("route.tlsInternal"),
                      },
                      { value: "off", label: t("route.tlsOff") },
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
                      label={t("route.serverIp")}
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
                      label={t("route.port")}
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
                  <Text tone="secondary">{t("route.listenHostHint")}</Text>
                </>
              )}
            </RouteSection>
            <RouteSection title={t("route.rules")}>
              <Switch
                id="route-form-enabled"
                label={t("routes.enabled")}
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={busy}
              />
              <Text tone="secondary">{t("route.unavailableFeatures")}</Text>
            </RouteSection>
            <RouteSection title={t("route.proxying")}>
              {isHttp ? (
                <>
                  <TextInput
                    id="http-target"
                    label={t("routes.serviceUrl")}
                    labelPlacement="above"
                    showIcon={false}
                    value={httpTarget}
                    onValueChange={(value) => {
                      setHttpTarget(value);
                      setError("");
                    }}
                    placeholder="http://127.0.0.1:8080"
                    hint={t("route.serviceUrlHint")}
                    required
                    disabled={busy}
                  />
                  <Switch
                    id="http-strip-prefix"
                    label={t("route.stripPrefix")}
                    hint={t("route.stripPrefixHint")}
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
                      label={t("route.serverIpOrDomain")}
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
                      label={t("route.port")}
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
                  <Text tone="secondary">{t("route.targetPortHint")}</Text>
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
                {route ? t("routes.save") : t("routes.create")}
              </Button>
              <Button
                type="button"
                variant="blank"
                onPress={onCancel}
                disabled={busy}
              >
                {t("nav.cancel")}
              </Button>
            </Stack>
          </Stack>
        </Card>
      </Stack>
    </form>
  );
}
