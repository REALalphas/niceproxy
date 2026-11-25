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
import { api, type DirectRule, type HttpRoute } from "./api";
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
    /^https?:\/\/(\[[^\]]+\]|[^:/?#@\\\[\]\s]+)(?::(\d*))?\/?#?$/i.exec(value);
  if (!match || !isDirectTarget(match[1].replace(/^\[|\]$/g, "")))
    return "Укажите HTTP(S)-адрес сервиса без пути, параметров и пароля.";
  if (match[2] !== undefined && !validPort(match[2]))
    return "Укажите порт сервиса от 1 до 65535.";
}

function RouteFlow({
  incoming,
  rules,
  upstream,
}: {
  incoming: string;
  rules: string;
  upstream: string;
}) {
  const steps = [
    {
      icon: "link",
      label: "Подключение",
      detail: incoming || "Укажите входящий адрес",
      mono: !!incoming,
    },
    { icon: "shield", label: "Правила", detail: rules, mono: false },
    {
      icon: "device",
      label: "Сервис",
      detail: upstream || "Укажите адрес сервиса",
      mono: !!upstream,
    },
  ] as const;
  return (
    <Card>
      <div className="route-flow-container">
        <ol className="route-flow" role="list" aria-label="Схема маршрута">
          {steps.map((step, index) => (
            <li className="route-flow-step" key={step.label}>
              <Icon name={step.icon} />
              <Text font="heading" weight="bold">
                {step.label}
              </Text>
              <div className="route-flow-detail">
                <Text font={step.mono ? "mono" : "ui"} tone="secondary">
                  {step.detail}
                </Text>
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
  initialProtocol = "http",
  onDone,
  onCancel,
}: {
  route?: Route;
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
    ? "Маршрут выключен"
    : isHttp
      ? "Совпадение по домену и пути"
      : "Прямой проброс";

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
        if (!httpHost) throw new Error("Укажите домен.");
        if (!pathValid)
          throw new Error(
            "Укажите буквальный путь от / без пробелов, управляющих символов, //, . и .., параметров и шаблонов (до 2048 байт).",
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
        errors.listenHost = "Укажите IP интерфейса или оставьте поле пустым.";
      if (!validPort(listenPort))
        errors.listenPort = "Укажите входящий порт от 1 до 65535.";
      if (!trimmedTargetHost)
        errors.targetHost = "Укажите IP-адрес или домен сервиса.";
      else if (!isDirectTarget(trimmedTargetHost))
        errors.targetHost =
          "Введите IP-адрес или домен без схемы, пути и порта.";
      if (targetPort && !validPort(targetPort))
        errors.targetPort =
          "Укажите порт от 1 до 65535 или оставьте поле пустым.";
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
        e instanceof Error ? e.message : "Не удалось сохранить маршрут.",
      );
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <Stack gap={4}>
        <RouteFlow incoming={incoming} rules={rules} upstream={upstream} />
        <Card>
          <Stack gap={5}>
            <RouteSection title="Точка подключения">
              {!httpRoute && (
                <Select
                  popup="overlay"
                  id="route-protocol"
                  label="Протокол"
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
                    aria-label="Домен и путь"
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
                          label="Домен"
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
                          label="Путь"
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
                          Например, / подходит для всех путей, а /api — для /api
                          и /api/users.
                        </Text>
                      </div>
                    </Stack>
                  </div>
                  <Select
                    popup="overlay"
                    id="tls"
                    label="TLS входящего соединения"
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
                    hint="Для всех путей одного домена используйте одинаковый режим."
                    disabled={busy}
                    options={[
                      { value: "auto", label: "Автоматически (HTTPS)" },
                      {
                        value: "internal",
                        label: "Внутренний сертификат (HTTPS)",
                      },
                      { value: "off", label: "Выключен (HTTP)" },
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
                      label="IP сервера"
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
                      label="Порт"
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
                    Оставьте IP пустым для приёма на всех интерфейсах.
                  </Text>
                </>
              )}
            </RouteSection>
            <RouteSection title="Правила">
              <Switch
                id="route-form-enabled"
                label="Маршрут включён"
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={busy}
              />
              <Text tone="secondary">
                Фильтры доступа, DDoS-защита и панель входа (Secured Route)
                недоступны в настройках маршрута.
              </Text>
            </RouteSection>
            <RouteSection title="Проксирование">
              {isHttp ? (
                <>
                  <TextInput
                    id="http-target"
                    label="URL сервиса"
                    labelPlacement="above"
                    showIcon={false}
                    value={httpTarget}
                    onValueChange={(value) => {
                      setHttpTarget(value);
                      setError("");
                    }}
                    placeholder="http://127.0.0.1:8080"
                    hint="Укажите HTTP(S)-адрес сервиса. Порт можно опустить, если он стандартный."
                    required
                    disabled={busy}
                  />
                  <Switch
                    id="http-strip-prefix"
                    label="Удалять префикс пути"
                    hint="Например, /api/users → /users. Параметры запроса сохраняются."
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
                      label="IP или домен"
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
                      label="Порт"
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
                    Если порт сервиса пуст, используется входящий порт.
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
                {route ? "Сохранить маршрут" : "Создать маршрут"}
              </Button>
              <Button
                type="button"
                variant="blank"
                onPress={onCancel}
                disabled={busy}
              >
                Отмена
              </Button>
            </Stack>
          </Stack>
        </Card>
      </Stack>
    </form>
  );
}
