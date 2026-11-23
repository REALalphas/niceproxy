import { useCallback, useEffect, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { installControlMotion } from "@alpha/core";
import {
  AppShell,
  Badge,
  Button,
  Card,
  IconButton,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@alpha/react";
import "@alpha/core/fonts.css";
import "@alpha/core/styles.css";
import "./app.css";
import { Cloudflare } from "./Cloudflare";
import { CloudflareOAuthWindow, isCloudflareOAuthWindow, type CloudflareCallback } from "./CloudflareOAuth";
import { cloudflareApi, type CloudflareStatus } from "./cloudflare-api";
import {
  api,
  type Auth,
  type DirectRule,
  type HttpRoute,
  type ProxyConfig,
  type ServiceHealth,
  Unauthorized,
} from "./api";
const err = (e: unknown) =>
  e instanceof Error ? e.message : "Произошла неизвестная ошибка.";
function ErrorMessage({ children }: { children: string }) {
  return (
    <div role="alert">
      <Text tone="default">{children}</Text>
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
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="alpha-ui auth-page">
      <Card>
        <form onSubmit={submit}>
          <Stack gap={5}>
            <Text as="h1" size="heading" font="heading">
              {initial.configured ? "Вход в Niceproxy" : "Первичная настройка"}
            </Text>
            <Text tone="secondary">
              {initial.configured
                ? "Введите пароль администратора."
                : "Создайте пароль администратора для управления прокси."}
            </Text>
            <TextInput
              id="password"
              label="Пароль"
              type="password"
              value={password}
              onValueChange={setPassword}
              required
              disabled={busy}
              autoComplete={
                initial.configured ? "current-password" : "new-password"
              }
            />
            {error && <ErrorMessage>{error}</ErrorMessage>}
            <Button type="submit" loading={busy} disabled={busy}>
              {initial.configured ? "Войти" : "Сохранить пароль"}
            </Button>
          </Stack>
        </form>
      </Card>
    </main>
  );
}
function Status({
  enabled,
  status,
  error,
}: {
  enabled: boolean;
  status: string;
  error?: string;
}) {
  return (
    <div className="status">
      <Badge
        value={
          !enabled
            ? "Выключено"
            : status === "healthy"
              ? "Применено"
              : status === "error"
                ? "Ошибка"
                : "Неизвестно"
        }
      />
      {error && <Text tone="muted">{error}</Text>}
    </div>
  );
}
function HttpForm({
  route,
  onDone,
  onCancel,
}: {
  route?: HttpRoute;
  onDone: (r: HttpRoute) => void;
  onCancel?: () => void;
}) {
  const [host, setHost] = useState(route?.host ?? "");
  const [target, setTarget] = useState(route?.target ?? "");
  const [path, setPath] = useState(route?.path ?? "/");
  const [stripPrefix, setStripPrefix] = useState(route?.stripPrefix ?? false);
  const [tls, setTls] = useState(route?.tls ?? "auto");
  const [enabled, setEnabled] = useState(route?.enabled ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    try {
      let u: URL;
      try {
        u = new URL(target);
      } catch {
        throw new Error(
          "Введите корректный целевой URL: http:// или https://.",
        );
      }
      if (!["http:", "https:"].includes(u.protocol))
        throw new Error("Цель должна начинаться с http:// или https://");
      if (!host.trim()) throw new Error("Укажите домен.");
      if (!path.startsWith("/") || /[?#\s]/.test(path))
        throw new Error("Путь должен начинаться с / и не содержать пробелы, ? или #.");
      setBusy(true);
      onDone(
        await api.saveHttp(
          {
            host: host.trim(),
            path,
            stripPrefix: path === "/" ? false : stripPrefix,
            target: target.trim(),
            tls: tls as HttpRoute["tls"],
            enabled,
          },
          route?.id,
        ),
      );
    } catch (e) {
      setError(err(e));
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack gap={3}>
        <Text as="h3" size="lg" font="heading">
          {route
            ? "Изменить HTTP/HTTPS маршрут"
            : "Добавить HTTP/HTTPS маршрут"}
        </Text>
        <div className="form-grid">
          <TextInput
            id="http-host"
            label="Домен"
            value={host}
            onValueChange={setHost}
            placeholder="example.com"
            required
            disabled={busy}
          />
          <TextInput
            id="http-path"
            label="Путь"
            value={path}
            onValueChange={(value) => {
              setPath(value);
              if (value === "/") setStripPrefix(false);
            }}
            placeholder="/api"
            hint="/api подходит для /api и /api/*, но не /apix. Более точный путь имеет приоритет; / подходит для всех путей. Регистр учитывается."
            required
            disabled={busy}
          />
          <TextInput
            id="http-target"
            label="Целевой URL"
            type="url"
            value={target}
            onValueChange={setTarget}
            placeholder="http://127.0.0.1:8080"
            required
            disabled={busy}
          />
          <Select
            id="tls"
            label="TLS"
            value={tls}
            onValueChange={(v) => setTls(v as HttpRoute["tls"])}
            disabled={busy}
            options={[
              { value: "auto", label: "Автоматически" },
              { value: "internal", label: "Внутренний сертификат" },
              { value: "off", label: "Выключен" },
            ]}
          />
        </div>
        <Text tone="secondary">
          По умолчанию путь и параметры запроса передаются без изменений.
          Для разных путей одного домена выбирайте одинаковый TLS.
        </Text>
        <Switch
          id="http-strip-prefix"
          label="Убирать префикс пути"
          hint="Например, /api/users → /users; параметры запроса сохраняются."
          checked={path !== "/" && stripPrefix}
          onCheckedChange={setStripPrefix}
          disabled={busy || path === "/"}
        />
        <Switch
          id="http-enabled"
          label="Включён"
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={busy}
        />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        <div className="actions">
          <Button type="submit" loading={busy} disabled={busy}>
            {route ? "Сохранить" : "Добавить"}
          </Button>
          {onCancel && (
            <Button type="button" variant="simple" onPress={onCancel} disabled={busy}>
              Отмена
            </Button>
          )}
        </div>
      </Stack>
    </form>
  );
}
function DirectForm({
  rule,
  onDone,
  onCancel,
}: {
  rule?: DirectRule;
  onDone: (r: DirectRule) => void;
  onCancel?: () => void;
}) {
  const [protocol, setProtocol] = useState(rule?.protocol ?? "tcp");
  const [listenHost, setListenHost] = useState(rule?.listenHost ?? "0.0.0.0");
  const [listenPort, setListenPort] = useState(String(rule?.listenPort ?? ""));
  const [targetHost, setTargetHost] = useState(rule?.targetHost ?? "");
  const [targetPort, setTargetPort] = useState(String(rule?.targetPort ?? ""));
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    const valid = (v: string) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
    if (!valid(listenPort) || !valid(targetPort) || !targetHost.trim()) {
      setError("Проверьте хосты и порты (1–65535).");
      return;
    }
    setBusy(true);
    setError("");
    try {
      onDone(
        await api.saveDirect(
          {
            protocol: protocol as DirectRule["protocol"],
            listenHost: listenHost.trim() || "0.0.0.0",
            listenPort: +listenPort,
            targetHost: targetHost.trim(),
            targetPort: +targetPort,
            enabled,
          },
          rule?.id,
        ),
      );
    } catch (e) {
      setError(err(e));
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack gap={3}>
        <Text as="h3" size="lg" font="heading">
          {rule ? "Изменить прямое правило" : "Добавить прямое правило"}
        </Text>
        <div className="form-grid">
          <Select
            id="protocol"
            label="Протокол"
            value={protocol}
            onValueChange={(v) => setProtocol(v as DirectRule["protocol"])}
            disabled={busy}
            options={[
              { value: "tcp", label: "TCP" },
              { value: "udp", label: "UDP" },
            ]}
          />
          <TextInput
            id="listen-host"
            label="Хост прослушивания"
            value={listenHost}
            onValueChange={setListenHost}
            placeholder="0.0.0.0"
            disabled={busy}
          />
          <TextInput
            id="listen-port"
            label="Порт прослушивания"
            value={listenPort}
            onValueChange={setListenPort}
            placeholder="8080"
            required
            disabled={busy}
          />
          <TextInput
            id="target-host"
            label="Целевой хост"
            value={targetHost}
            onValueChange={setTargetHost}
            placeholder="127.0.0.1"
            required
            disabled={busy}
          />
          <TextInput
            id="target-port"
            label="Целевой порт"
            value={targetPort}
            onValueChange={setTargetPort}
            placeholder="80"
            required
            disabled={busy}
          />
        </div>
        <Switch
          id="direct-enabled"
          label="Включено"
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={busy}
        />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        <div className="actions">
          <Button type="submit" loading={busy} disabled={busy}>
            {rule ? "Сохранить" : "Добавить"}
          </Button>
          {onCancel && (
            <Button type="button" variant="simple" onPress={onCancel} disabled={busy}>
              Отмена
            </Button>
          )}
        </div>
      </Stack>
    </form>
  );
}
function sectionFromHash() {
  const section = window.location.hash.slice(1);
  return ["overview", "routes", "cloudflare"].includes(section) ? section : "overview";
}
function App({ cloudflareCallback }: { cloudflareCallback?: CloudflareCallback }) {
  const [auth, setAuth] = useState<Auth | null>(null);
  const [config, setConfig] = useState<ProxyConfig | null>(null);
  const [health, setHealth] = useState<ServiceHealth | null>(null);
  const [cloudflareStatus, setCloudflareStatus] = useState<CloudflareStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [section, setSection] = useState(sectionFromHash);
  useEffect(() => {
    const changed = () => setSection(sectionFromHash());
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  const [editing, setEditing] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [creationKind, setCreationKind] = useState("http");
  const [filter, setFilter] = useState("all");
  const [pending, setPending] = useState<Set<string>>(new Set());
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const a = await api.auth();
      setAuth(a);
      if (a.authenticated) {
        const [c, h, cf] = await Promise.all([api.config(), api.health(), cloudflareApi.status()]);
        setConfig(c);
        setHealth(h);
        setCloudflareStatus(cf);
      }
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(err(e));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
    const f = () => {
      setAuth(null);
      setConfig(null);
      setHealth(null);
      setCloudflareStatus(null);
      void load();
    };
    const changed = () => void load();
    window.addEventListener("niceproxy:unauthorized", f);
    window.addEventListener("niceproxy:changed", changed);
    return () => {
      window.removeEventListener("niceproxy:unauthorized", f);
      window.removeEventListener("niceproxy:changed", changed);
    };
  }, [load]);
  if (loading && !auth)
    return (
      <main className="alpha-ui auth-page">
        <Text>Загрузка…</Text>
      </main>
    );
  if (auth && !auth.authenticated)
    return <AuthScreen initial={auth} onAuthenticated={() => void load()} />;
  if (!config)
    return (
      <main className="alpha-ui page">
        <Card>
          <Stack gap={3}>
            <Text as="h1" size="heading" font="heading">
              Niceproxy
            </Text>
            <Text>{error || "Конфигурация недоступна."}</Text>
            <Button onPress={() => void load()} loading={loading}>
              Повторить
            </Button>
          </Stack>
        </Card>
      </main>
    );
  const upsert = (kind: "http" | "direct", item: HttpRoute | DirectRule) => {
    setConfig(
      (c) =>
        c && {
          ...c,
          [kind === "http" ? "httpRoutes" : "directRules"]: (kind === "http"
            ? c.httpRoutes
            : c.directRules
          ).some((x) => x.id === item.id)
            ? (kind === "http" ? c.httpRoutes : c.directRules).map((x) =>
                x.id === item.id ? item : x,
              )
            : [...(kind === "http" ? c.httpRoutes : c.directRules), item],
        },
    );
    setEditing(null);
    setAdding(false);
  };
  async function remove(kind: "http-routes" | "direct-rules", id: string) {
    const key = `${kind}:${id}`;
    setPending((current) => new Set(current).add(key));
    try {
      await api.remove(kind, id);
      setConfig(
        (c) =>
          c && {
            ...c,
            [kind === "http-routes" ? "httpRoutes" : "directRules"]: (kind ===
            "http-routes"
              ? c.httpRoutes
              : c.directRules
            ).filter((x) => x.id !== id),
          },
      );
    } catch (e) {
      setError(err(e));
    } finally {
      setPending((current) => { const next = new Set(current); next.delete(key); return next; });
    }
  }
  async function toggle(kind: "http-routes" | "direct-rules", id: string, enabled: boolean) {
    const key = `${kind}:${id}`;
    setPending((current) => new Set(current).add(key));
    try {
      const item = await api.toggle(kind, id, enabled);
      // A toggle should not close another mapping's open form.
      setConfig((current) => current && (kind === "http-routes"
        ? { ...current, httpRoutes: current.httpRoutes.map((r) => r.id === id ? item as HttpRoute : r) }
        : { ...current, directRules: current.directRules.map((r) => r.id === id ? item as DirectRule : r) }));
    } catch (e) {
      setError(err(e));
    } finally {
      setPending((current) => { const next = new Set(current); next.delete(key); return next; });
    }
  }
  const mappings = [
    ...config.httpRoutes.map((route) => ({ kind: "http-routes" as const, route })),
    ...config.directRules.map((route) => ({ kind: "direct-rules" as const, route })),
  ].filter(({ route }) => filter === "all" || ("host" in route ? filter === "http" : filter === route.protocol));
  const callbackUrl = cloudflareStatus?.redirectUrl ?? "";
  const nav = [
    { id: "overview", label: "Обзор", icon: "home" as const },
    { id: "routes", label: "Маршруты", icon: "link" as const,
      notifications: config.httpRoutes.length + config.directRules.length },
    { id: "cloudflare", label: "Cloudflare", icon: "link" as const },
  ];
  return (
    <AppShell
      serviceName="Niceproxy"
      items={nav}
      selectedId={section}
      onSelect={(id) => {
        setSection(id);
        window.location.hash = id;
        setAdding(false);
        setEditing(null);
      }}
    >
      <main className="page">
        <header className="hero">
          <div>
            <Text as="h1" size="heading" font="heading">
              {section === "overview"
                ? "Обзор"
                : section === "cloudflare" ? "Cloudflare" : "Маршруты"}
            </Text>
            {section !== "cloudflare" && <Text tone="secondary">
              Управление маршрутизацией и состоянием применения
            </Text>}
          </div>
          <div className="actions">
            <Button
              variant="simple"
              onPress={() => void load()}
              loading={loading}
            >
              Обновить
            </Button>
            <Button
              variant="simple"
              onPress={() =>
                void api
                  .logout()
                  .then(() => {
                    setConfig(null);
                    setAuth({ configured: true, authenticated: false });
                  })
                  .catch((e) => setError(err(e)))
              }
            >
              Выйти
            </Button>
          </div>
        </header>
        {error && (
          <Card>
            <ErrorMessage>{error}</ErrorMessage>
          </Card>
        )}
        {section === "cloudflare" && <Cloudflare routes={config.httpRoutes} callback={cloudflareCallback} />}
        {section === "overview" && (
          <Stack gap={5}>
            <Card>
              <Stack gap={3}>
                <Text as="h2" size="xl" font="heading">
                  Состояние сервиса
                </Text>
                <div className="stats">
                  <Text>
                    Сохранённая ревизия: <strong>{config.revision}</strong>
                  </Text>
                  <Text>
                    Применённая ревизия:{" "}
                    <strong>{health && health.appliedRevision < 0 ? "Частичное применение" : (health?.appliedRevision ?? "—")}</strong>
                  </Text>
                  <Text>
                    Состояние: <strong>{health?.status === "healthy" ? "Конфигурация применена" : health?.status === "error" ? "Ошибка применения" : "—"}</strong>
                  </Text>
                  <Text>Caddy: {health ? (health.caddy ? "Доступен" : "Недоступен") : "—"}</Text>
                </div>
                {health && health.appliedRevision !== config.revision && (
                  <Text>
                    Сохранённая конфигурация ещё не применена полностью.
                  </Text>
                )}
                {health?.error && <ErrorMessage>{health.error}</ErrorMessage>}
                <Button variant="simple" onPress={() => void api.reconcile().then(() => load()).catch((e) => setError(err(e)))} disabled={loading}>
                  Применить повторно
                </Button>
              </Stack>
            </Card>
            <Card>
              <Text>Маршрутов HTTP/HTTPS: {config.httpRoutes.length}</Text>
              <Text>Прямых правил: {config.directRules.length}</Text>
            </Card>
          </Stack>
        )}
        {section === "routes" && (
          <Stack gap={4}>
            <div className="section-heading">
              <div className="route-filter">
                <Select
                  id="route-filter"
                  label="Показать"
                  value={filter}
                  onValueChange={setFilter}
                  options={[
                    { value: "all", label: "Все маршруты" },
                    { value: "http", label: "HTTP/HTTPS" },
                    { value: "tcp", label: "TCP" },
                    { value: "udp", label: "UDP" },
                  ]}
                />
              </div>
              {!adding && <Button onPress={() => { setEditing(null); setAdding(true); }}>Добавить маршрут</Button>}
            </div>
            {adding && (
              <Card>
                <Stack gap={4}>
                  <Select
                    id="creation-kind"
                    label="Тип маршрута"
                    value={creationKind}
                    onValueChange={setCreationKind}
                    options={[
                      { value: "http", label: "HTTP/HTTPS — домен и путь" },
                      { value: "direct", label: "TCP/UDP — проброс порта" },
                    ]}
                  />
                  {creationKind === "http" ? (
                    <HttpForm onDone={(r) => upsert("http", r)} onCancel={() => setAdding(false)} />
                  ) : (
                    <DirectForm onDone={(r) => upsert("direct", r)} onCancel={() => setAdding(false)} />
                  )}
                </Stack>
              </Card>
            )}
            {cloudflareStatus && (
              <Card>
                <Stack gap={2}>
                  <Text as="h2" size="xl" font="heading">Cloudflare callback</Text>
                  {callbackUrl
                    ? <>
                      <Text font="mono">{callbackUrl}</Text>
                      <Text tone="secondary">Служебный callback для входа через Cloudflare. Он не создаёт отдельное правило Caddy. DNS и HTTPS reverse proxy для домена настраиваются отдельно.</Text>
                    </>
                    : <Text tone="secondary">Callback не настроен. Откройте раздел Cloudflare и укажите локальный URL или домен с субдоменом.</Text>}
                  <div className="actions">
                    <Button variant="simple" onPress={() => { setSection("cloudflare"); window.location.hash = "cloudflare"; setAdding(false); setEditing(null); }}>Настроить в Cloudflare</Button>
                  </div>
                </Stack>
              </Card>
            )}
            {mappings.length === 0 && (
              <Card><Text tone="muted">{filter === "all" ? "Маршрутов пока нет." : "Нет маршрутов выбранного типа."}</Text></Card>
            )}
            {mappings.map(({ kind, route }) => {
              const key = `${kind}:${route.id}`;
              const isHttp = "host" in route;
              const endpoint = (host: string, port: number) => `${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${port}`;
              const mapping = isHttp
                ? `${route.host}${route.path === "/" ? "" : route.path} → ${route.target}`
                : `${route.protocol.toUpperCase()} ${endpoint(route.listenHost === "0.0.0.0" ? "" : route.listenHost, route.listenPort)} → ${endpoint(route.targetHost, route.targetPort)}`;
              return (
                <Card key={key}>
                  {editing === key ? (
                    isHttp
                      ? <HttpForm route={route} onDone={(r) => upsert("http", r)} onCancel={() => setEditing(null)} />
                      : <DirectForm rule={route} onDone={(r) => upsert("direct", r)} onCancel={() => setEditing(null)} />
                  ) : (
                    <div className="route-row">
                      <div className="route-mapping"><Text as="span" font="mono">{mapping}</Text></div>
                      <div className="route-status"><Status {...route} /></div>
                      <div className="actions">
                        <Switch
                          id={`enabled-${key}`}
                          label="Включён"
                          checked={route.enabled}
                          disabled={pending.has(key)}
                          onCheckedChange={(enabled) => void toggle(kind, route.id, enabled)}
                        />
                        <IconButton icon="edit" label={`Изменить маршрут ${mapping}`} disabled={pending.has(key)} onPress={() => { setAdding(false); setEditing(key); }} />
                        <IconButton icon="trash" label={`Удалить маршрут ${mapping}`} disabled={pending.has(key)} onPress={() => void remove(kind, route.id)} />
                      </div>
                    </div>
                  )}
                </Card>
              );
            })}
          </Stack>
        )}
      </main>
    </AppShell>
  );
}
const root = createRoot(document.getElementById("root")!);
const dispose = installControlMotion();
const url = new URL(window.location.href);
const cloudflareStage = url.searchParams.get("cloudflare");
const isOAuthWindow = isCloudflareOAuthWindow();
const callback: CloudflareCallback | undefined = cloudflareStage === "connected" || cloudflareStage === "error"
  ? cloudflareStage
  : undefined;
const oauthStage = cloudflareStage === "authorizing" ? "authorizing" : callback;
if (callback || cloudflareStage === "authorizing" && !isOAuthWindow) {
  url.searchParams.delete("cloudflare");
  window.history.replaceState(null, "", url);
}
root.render(
  isOAuthWindow && oauthStage
    ? <CloudflareOAuthWindow stage={oauthStage} />
    : <App cloudflareCallback={callback} />,
);
if (import.meta.hot)
  import.meta.hot.dispose(() => {
    root.unmount();
    dispose();
  });
