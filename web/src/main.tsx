import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { createRoot } from "react-dom/client";
import { installControlMotion } from "@alpha/core";
import {
  AppShell,
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
  TextInput,
} from "@alpha/react";
import "@alpha/core/fonts.css";
import "@alpha/core/styles.css";
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
  type ServiceHealth,
  Unauthorized,
} from "./api";

const err = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось выполнить действие.";
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
function PortOwnersCard({
  settings,
  error,
  onSaved,
}: {
  settings: PortOwnerSettings | null;
  error: string;
  onSaved: (config: ProxyConfig) => void;
}) {
  const [draft, setDraft] = useState<Partial<PortOwners>>({});
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState("");
  const value = settings ? { ...settings.owners, ...draft } : null;
  const dirty =
    !!settings &&
    Object.entries(draft).some(
      ([key, owner]) => settings.owners[key as keyof PortOwners] !== owner,
    );
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!value || !settings || error || busy) return;
    setBusy(true);
    setSaveError("");
    try {
      const config = await api.savePortOwners(draft);
      onSaved(config);
      setDraft({});
    } catch (e) {
      setSaveError(err(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack gap={3}>
        <Text tone="secondary">
          Выберите HTTP/HTTPS или прямой проброс для каждого порта. Перед сменой
          отключите конфликтующие маршруты.
        </Text>
        {error && <ErrorMessage>{error}</ErrorMessage>}
        {settings && value && (
          <Stack gap={4}>
            {(
              [
                [
                  "http",
                  `HTTP · TCP ${settings.httpPort}`,
                  "Caddy — HTTP",
                  "Прямой TCP",
                ],
                [
                  "https",
                  `HTTPS · TCP ${settings.httpsPort}`,
                  "Caddy — HTTPS",
                  "Прямой TCP",
                ],
                [
                  "http3",
                  `HTTP/3 · UDP ${settings.httpsPort}`,
                  "Caddy — HTTP/3",
                  "Прямой UDP",
                ],
              ] as const
            ).map(([key, label, caddyLabel, directLabel]) => (
              <Select
                popup="overlay"
                key={key}
                id={`port-owner-${key}`}
                label={label}
                value={value[key]}
                onValueChange={(owner) => {
                  if (owner === "caddy" || owner === "direct") {
                    setDraft((current) => ({ ...current, [key]: owner }));
                    setSaveError("");
                  }
                }}
                disabled={busy || !!error}
                options={[
                  { value: "caddy", label: caddyLabel },
                  { value: "direct", label: directLabel },
                ]}
              />
            ))}
          </Stack>
        )}
        <Text tone="secondary">
          Сохранение и применение — отдельные состояния. Результат доступен в
          разделе «Сервис».
        </Text>
        {saveError && <ErrorMessage>{saveError}</ErrorMessage>}
        <Stack direction="row" gap={3}>
          <Button
            type="submit"
            disabled={!settings || !!error || busy || !dirty}
            loading={busy}
          >
            Сохранить назначения
          </Button>
        </Stack>
      </Stack>
    </form>
  );
}
function readPage() {
  const hash = window.location.hash.slice(1);
  if (hash === "cloudflare" || hash === "settings/cloudflare")
    return "settings/cloudflare";
  if (
    hash === "settings/ports" ||
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
  const [ownersError, setOwnersError] = useState("");
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
          setOwnersError("");
        } else setOwnersError(err(o.reason));
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
      : page === "settings/ports"
        ? "Назначение портов"
        : page === "settings/cloudflare"
          ? "Cloudflare DNS"
          : page === "settings/account"
            ? "Доступ к панели"
            : page === "settings"
              ? "Настройки"
              : isList
                ? "Маршруты"
                : isCreating
                  ? "Новый маршрут"
                  : mode === "edit"
                    ? "Редактирование маршрута"
                    : mode === "delete"
                      ? "Удаление маршрута"
                      : "Маршрут";
  const converged =
    !!health &&
    health.appliedRevision === config.revision &&
    health.revision === config.revision;
  const applied = converged && health?.state === "ready";
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
      <Page width={isList ? "content" : "form"} gap={6}>
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
                Caddy:{" "}
                {!health
                  ? "состояние неизвестно"
                  : health.caddy === true || health.caddy === "healthy"
                    ? "доступен"
                    : health.caddy === false || health.caddy === "error"
                      ? "недоступен"
                      : String(health.caddy)}
              </Text>
              {health?.error && <ErrorMessage>{health.error}</ErrorMessage>}
              {certificate && (
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
              {panelDomainSettings?.proxyWarning && (
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
                label="Назначение портов"
                secondaryText="HTTP/HTTPS или прямой TCP/UDP"
                secondaryPlacement="below"
                icon="device"
                onPress={() => navigate("settings/ports")}
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
        {page === "settings/ports" && (
          <PortOwnersCard
            settings={owners}
            error={ownersError}
            onSaved={(next) => {
              if (renderEpoch !== epoch.current || !authenticated.current)
                return;
              setConfig(next);
              setOwners(
                (current) => current && { ...current, owners: next.portOwners },
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
