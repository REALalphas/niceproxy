import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import {
  Button,
  Card,
  DrawerButton,
  DrawerDivider,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@alpha/react";
import { changeView } from "./view";
import { type HttpRoute, Unauthorized } from "./api";
import {
  authorizationURL,
  cloudflareApi,
  parseScopes,
  supportedRecord,
  type CloudflareStatus,
  type DNSRecord,
  type RecordInput,
  type Zone,
} from "./cloudflare-api";
const message = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось выполнить действие.";
function Alert({ children }: { children: string }) {
  return (
    <div role="alert">
      <Text>{children}</Text>
    </div>
  );
}

function RecordForm({
  zone,
  record,
  routes,
  onSaved,
  onCancel,
}: {
  zone: Zone;
  record?: DNSRecord;
  routes: HttpRoute[];
  onSaved: (record: DNSRecord) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(record?.name ?? "");
  const [type, setType] = useState<RecordInput["type"]>(
    record && supportedRecord(record.type) ? record.type : "A",
  );
  const [content, setContent] = useState(record?.content ?? "");
  const [proxied, setProxied] = useState(record?.proxied ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const suggestions = [
    ...new Set(
      routes
        .map((r) => r.host.toLowerCase())
        .filter(
          (host) =>
            host === zone.name.toLowerCase() ||
            host.endsWith(`.${zone.name.toLowerCase()}`),
        ),
    ),
  ];
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy || !name.trim() || !content.trim()) return;
    setBusy(true);
    setError("");
    try {
      onSaved(
        await cloudflareApi.saveRecord(
          zone.id,
          {
            name: name.trim(),
            type,
            content: content.trim(),
            proxied,
            ttl: record?.ttl ?? 1,
          },
          record?.id,
        ),
      );
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack gap={4}>
        <Text as="h3" size="xl" font="heading" weight="bold">
          {record ? "Изменить DNS-запись" : "Новая DNS-запись"}
        </Text>
        <Stack gap={4}>
          <TextInput
            showIcon={false}
            labelPlacement="inside"
            id="cf-record-name"
            label="Имя DNS-записи"
            value={name}
            onValueChange={setName}
            required
            disabled={busy}
            hint={`Полное имя в зоне ${zone.name}`}
          />
          <Select
            popup="overlay"
            id="cf-record-type"
            label="Тип"
            value={type}
            onValueChange={(v) => {
              if (supportedRecord(v)) setType(v);
            }}
            disabled={busy}
            options={["A", "AAAA", "CNAME"].map((value) => ({
              value,
              label: value,
            }))}
          />
          <TextInput
            showIcon={false}
            labelPlacement="inside"
            id="cf-record-content"
            label={
              type === "CNAME"
                ? "Целевое доменное имя"
                : type === "AAAA"
                  ? "IPv6-адрес"
                  : "IPv4-адрес"
            }
            value={content}
            onValueChange={setContent}
            required
            disabled={busy}
            hint="Введите значение вручную, без схемы, пути и порта."
          />
        </Stack>
        {suggestions.length > 0 && (
          <Select
            popup="overlay"
            id="cf-route-suggestion"
            label="Подставить имя из HTTP-маршрута"
            value=""
            onValueChange={(v) => {
              if (v) setName(v);
            }}
            disabled={busy}
            options={[
              { value: "", label: "Выберите имя (необязательно)" },
              ...suggestions.map((value) => ({ value, label: value })),
            ]}
          />
        )}
        <Switch
          id="cf-proxied"
          label="Cloudflare proxy"
          checked={proxied}
          onCheckedChange={setProxied}
          disabled={busy}
          hint="Выключено: DNS only. Обычный прокси Cloudflare не обслуживает произвольные TCP/UDP-порты."
        />
        <Text tone="secondary">
          DNS не содержит путей и портов. TTL:{" "}
          {record && record.ttl !== 1
            ? `${record.ttl} секунд (сохраняется)`
            : "автоматически"}
          .
        </Text>
        <Text font="mono">
          Предпросмотр: {type} {name.trim() || "имя"} →{" "}
          {content.trim() || "значение"} ·{" "}
          {proxied ? "Cloudflare proxy" : "DNS only"}
        </Text>
        {error && <Alert>{error}</Alert>}
        <Stack direction="row" gap={3}>
          <Button
            type="submit"
            loading={busy}
            disabled={busy || !name.trim() || !content.trim()}
          >
            {record ? "Сохранить DNS-запись" : "Создать DNS-запись"}
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
    </form>
  );
}

export function Cloudflare({
  routes = [],
  callback,
}: {
  routes?: HttpRoute[];
  callback?: string;
}) {
  const [status, setStatus] = useState<CloudflareStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [setup, setSetup] = useState(false);
  const [clientId, setClientId] = useState("");
  const [scopes, setScopes] = useState("");
  const [zones, setZones] = useState<Zone[]>([]);
  const [zoneId, setZoneId] = useState("");
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const recordsVersion = useRef(0);
  const [zonesLoading, setZonesLoading] = useState(false);
  const [zonesError, setZonesError] = useState("");
  const [recordsLoading, setRecordsLoading] = useState(false);
  const [recordsError, setRecordsError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState<DNSRecord | "new" | null>(null);
  const applyStatus = useCallback((s: CloudflareStatus) => {
    setStatus(s);
    setClientId(s.clientId);
    setScopes(s.scopes.join(" "));
    if (!s.connected) {
      setZones([]);
      setZoneId("");
      setRecords([]);
      setEditor(null);
    }
  }, []);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      applyStatus(await cloudflareApi.status());
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(message(e));
    } finally {
      setLoading(false);
    }
  }, [applyStatus]);
  useEffect(() => {
    void load();
  }, [load]);
  useEffect(() => {
    if (!status?.connected) return;
    let current = true;
    setZonesLoading(true);
    setZonesError("");
    cloudflareApi
      .zones()
      .then((data) => {
        if (current) setZones(data.zones);
      })
      .catch((e) => {
        if (current && !(e instanceof Unauthorized)) setZonesError(message(e));
      })
      .finally(() => {
        if (current) setZonesLoading(false);
      });
    return () => {
      current = false;
    };
  }, [status?.connected, refresh]);
  useEffect(() => {
    setRecordsError("");
    if (!status?.connected || !zoneId) {
      setRecords([]);
      setRecordsLoading(false);
      return;
    }
    let current = true;
    const version = recordsVersion.current;
    setRecordsLoading(true);
    cloudflareApi
      .records(zoneId)
      .then((data) => {
        if (current && version === recordsVersion.current)
          setRecords(data.records);
      })
      .catch((e) => {
        if (
          current &&
          version === recordsVersion.current &&
          !(e instanceof Unauthorized)
        )
          setRecordsError(message(e));
      })
      .finally(() => {
        if (current) setRecordsLoading(false);
      });
    return () => {
      current = false;
    };
  }, [zoneId, status?.connected, refresh]);
  async function action(run: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await run();
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  function saveSettings(e: FormEvent) {
    e.preventDefault();
    if (!clientId.trim() || !parseScopes(scopes).length) return;
    void action(async () => {
      applyStatus(
        await cloudflareApi.settings(clientId.trim(), parseScopes(scopes)),
      );
      setSetup(false);
      setNotice("Настройки сохранены. Войдите в аккаунт Cloudflare заново.");
    });
  }
  const zone = zones.find((z) => z.id === zoneId);
  const change = (update: () => void) => {
    void changeView(update);
  };
  if (setup && status)
    return (
      <form onSubmit={saveSettings}>
        <Stack gap={4}>
          <Text as="h2" size="xl" font="heading">
            Подключение Cloudflare
          </Text>
          <Text tone="secondary">
            Зарегистрируйте OAuth-приложение с PKCE и скопируйте его Client ID и
            разрешения.
          </Text>
          <Text>
            <a
              href="https://dash.cloudflare.com/?to=/:account/oauth-clients"
              target="_blank"
              rel="noreferrer"
            >
              Создать OAuth-приложение
            </a>{" "}
            ·{" "}
            <a
              href="https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/"
              target="_blank"
              rel="noreferrer"
            >
              Инструкция Cloudflare
            </a>
          </Text>
          <TextInput
            showIcon={false}
            id="cf-callback"
            label="Redirect URI"
            labelPlacement="inside"
            value={status.redirectUrl}
            readOnly
          />
          <TextInput
            showIcon={false}
            id="cf-client-id"
            label="OAuth Client ID"
            labelPlacement="inside"
            value={clientId}
            onValueChange={setClientId}
            required
            disabled={busy}
          />
          <TextInput
            showIcon={false}
            id="cf-scopes"
            label="Scope ID"
            labelPlacement="inside"
            value={scopes}
            onValueChange={setScopes}
            hint="Zone Read, DNS Read, DNS Write; offline_access для обновления доступа. ID через пробел или запятую."
            required
            disabled={busy}
          />
          <Text tone="secondary">
            Private · response type: code · grant types: authorization_code,
            refresh_token · authentication: none · PKCE: S256. Сохранение
            отключит текущее подключение.
          </Text>
          {error && <Alert>{error}</Alert>}
          <Stack direction="row" gap={3}>
            <Button
              type="submit"
              loading={busy}
              disabled={!clientId.trim() || !parseScopes(scopes).length}
            >
              Сохранить подключение
            </Button>
            <Button
              variant="blank"
              disabled={busy}
              onPress={() => change(() => setSetup(false))}
            >
              Отмена
            </Button>
          </Stack>
        </Stack>
      </form>
    );
  if (zone && editor)
    return (
      <RecordForm
        key={`${zone.id}:${editor === "new" ? "new" : editor.id}`}
        zone={zone}
        record={editor === "new" ? undefined : editor}
        routes={routes}
        onCancel={() => change(() => setEditor(null))}
        onSaved={(saved) => {
          ++recordsVersion.current;
          setRecords((current) =>
            current.some((r) => r.id === saved.id)
              ? current.map((r) => (r.id === saved.id ? saved : r))
              : [...current, saved],
          );
          change(() => setEditor(null));
        }}
      />
    );
  return (
    <Stack gap={5}>
      <Stack gap={2}>
        <Text tone="secondary">
          {loading && !status
            ? "Подключение…"
            : !status
              ? "Состояние недоступно"
              : status.connected
                ? "Аккаунт подключён"
                : status.configured
                  ? "Войдите в аккаунт для управления DNS."
                  : "Подключите Cloudflare для управления DNS-записями."}
        </Text>
      </Stack>
      {callback === "error" && (
        <Alert>
          Не удалось подключить Cloudflare. Повторите вход или проверьте
          настройки.
        </Alert>
      )}
      {callback === "connected" && status?.connected && (
        <Text>Cloudflare успешно подключён.</Text>
      )}
      {status?.error && <Alert>{status.error}</Alert>}
      {error && <Alert>{error}</Alert>}
      {notice && (
        <div role="status">
          <Text>{notice}</Text>
        </div>
      )}
      {!status?.connected && (
        <Stack direction="row" gap={3}>
          {status && !status.configured && (
            <Button onPress={() => change(() => setSetup(true))}>
              Подключить Cloudflare
            </Button>
          )}
          {status?.configured && (
            <Button
              loading={busy}
              onPress={() =>
                void action(async () => {
                  const result = await cloudflareApi.connect();
                  window.location.assign(authorizationURL(result.url));
                })
              }
            >
              Войти через Cloudflare
            </Button>
          )}
          <Button variant="blank" loading={loading} onPress={() => void load()}>
            Обновить
          </Button>
        </Stack>
      )}
      {status?.connected && (
        <Stack gap={4}>
          {zonesLoading && !zones.length && <Text>Загрузка зон…</Text>}
          {zonesError && <Alert>{zonesError}</Alert>}
          {!zonesLoading && !zonesError && !zones.length && (
            <Text>Нет доступных зон. Проверьте разрешения подключения.</Text>
          )}
          {!!zones.length && (
            <Select
              popup="overlay"
              id="cf-zone"
              label="Доменная зона"
              value={zoneId}
              onValueChange={(value) => {
                ++recordsVersion.current;
                setRecords([]);
                setZoneId(value);
              }}
              options={[
                { value: "", label: "Выберите зону" },
                ...zones.map((z) => ({
                  value: z.id,
                  label: `${z.name} · ${z.account.name} · ${z.status}`,
                })),
              ]}
            />
          )}
          <Stack direction="row" gap={3}>
            {zone && (
              <Button
                onPress={() => change(() => setEditor("new"))}
                disabled={recordsLoading}
              >
                Добавить DNS-запись
              </Button>
            )}
            <Button
              variant="blank"
              loading={zonesLoading || recordsLoading}
              onPress={() => setRefresh((v) => v + 1)}
            >
              Обновить
            </Button>
          </Stack>
          {recordsLoading && !records.length && (
            <Text>Загрузка DNS-записей…</Text>
          )}
          {recordsError && <Alert>{recordsError}</Alert>}
          {zone && !recordsLoading && !recordsError && !records.length && (
            <Text tone="secondary">DNS-записей пока нет.</Text>
          )}
          <Stack gap={4}>
            {records.map((record) => (
              <Card key={record.id}>
                <Stack gap={3}>
                  <Text font="heading" weight="bold">
                    {record.type}
                  </Text>
                  <Text font="mono">{record.name}</Text>
                  <Text font="mono">{record.content}</Text>
                  <Text tone="secondary">
                    {record.proxied ? "Cloudflare proxy" : "DNS only"} · TTL{" "}
                    {record.ttl === 1 ? "Auto" : record.ttl}
                  </Text>
                  {supportedRecord(record.type) ? (
                    <Button
                      variant="simple"
                      onPress={() => {
                        ++recordsVersion.current;
                        change(() => setEditor(record));
                      }}
                    >
                      Изменить DNS-запись
                    </Button>
                  ) : (
                    <Text tone="muted">
                      Этот тип доступен только для просмотра.
                    </Text>
                  )}
                </Stack>
              </Card>
            ))}
          </Stack>
          <Text tone="muted">
            DNS хранит адреса без путей и портов. Cloudflare proxy не
            обслуживает произвольные TCP/UDP-порты.
          </Text>
        </Stack>
      )}
      {status?.configured && (
        <Stack gap={1}>
          <DrawerDivider label="Подключение" />
          <DrawerButton
            label="Настройки OAuth"
            icon="settings"
            onPress={() => change(() => setSetup(true))}
          />
          {status.connected && (
            <Button
              variant="blank"
              loading={busy}
              onPress={() =>
                void action(async () => {
                  const result = await cloudflareApi.disconnect();
                  applyStatus({
                    ...status,
                    connected: false,
                    expiresAt: undefined,
                    error: undefined,
                  });
                  setNotice(
                    result.warning
                      ? `Аккаунт отключён локально. ${result.warning}`
                      : "Аккаунт отключён.",
                  );
                })
              }
            >
              Отключить Cloudflare
            </Button>
          )}
          {status.error && (
            <Text>
              <a
                href="https://dash.cloudflare.com/?to=/profile/access-management/authorization"
                target="_blank"
                rel="noreferrer"
              >
                Проверить и отозвать доступ
              </a>
            </Text>
          )}
          {status.connected && status.expiresAt && (
            <Text tone="muted">Доступ действует до {status.expiresAt}</Text>
          )}
        </Stack>
      )}
    </Stack>
  );
}
