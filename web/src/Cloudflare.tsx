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
  e instanceof Error ? e.message : "Failed to complete action.";
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
          {record ? "Edit DNS record" : "New DNS record"}
        </Text>
        <Stack gap={4}>
          <TextInput
            showIcon={false}
            labelPlacement="inside"
            id="cf-record-name"
            label="DNS record name"
            value={name}
            onValueChange={setName}
            required
            disabled={busy}
            hint={`Full name in zone ${zone.name}`}
          />
          <Select
            popup="overlay"
            id="cf-record-type"
            label="Type"
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
                ? "Target domain name"
                : type === "AAAA"
                  ? "IPv6 address"
                  : "IPv4 address"
            }
            value={content}
            onValueChange={setContent}
            required
            disabled={busy}
            hint="Enter the value manually without scheme, path, or port."
          />
        </Stack>
        {suggestions.length > 0 && (
          <Select
            popup="overlay"
            id="cf-route-suggestion"
            label="Fill name from HTTP route"
            value=""
            onValueChange={(v) => {
              if (v) setName(v);
            }}
            disabled={busy}
            options={[
              { value: "", label: "Select a name (optional)" },
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
          hint="Off: DNS only. Standard Cloudflare proxy does not serve arbitrary TCP/UDP ports."
        />
        <Text tone="secondary">
          DNS does not contain paths or ports. TTL:{" "}
          {record && record.ttl !== 1
            ? `${record.ttl} seconds (preserved)`
            : "automatic"}
          .
        </Text>
        <Text font="mono">
          Preview: {type} {name.trim() || "name"} →{" "}
          {content.trim() || "value"} ·{" "}
          {proxied ? "Cloudflare proxy" : "DNS only"}
        </Text>
        {error && <Alert>{error}</Alert>}
        <Stack direction="row" gap={3}>
          <Button
            type="submit"
            loading={busy}
            disabled={busy || !name.trim() || !content.trim()}
          >
            {record ? "Save DNS record" : "Create DNS record"}
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
  const [authorization, setAuthorization] = useState("");
  const [callbackURL, setCallbackURL] = useState("");
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
      setNotice("Settings saved. Sign in to your Cloudflare account again.");
    });
  }
  const loopback = status?.loopbackRedirectUrl;
  const direct = status?.redirectUrl.startsWith(window.location.origin + "/");
  const useLoopback = !!loopback;

  async function startOAuth(localhost: boolean) {
    const result = await cloudflareApi.connect(localhost);
    const url = authorizationURL(result.url);
    setCallbackURL("");
    if (localhost) setAuthorization(url);
    else window.location.assign(url);
  }

  function finishOAuth(e: FormEvent) {
    e.preventDefault();
    if (!callbackURL.trim()) return;
    void action(async () => {
      applyStatus(await cloudflareApi.complete(callbackURL.trim()));
      setAuthorization("");
      setCallbackURL("");
      setNotice("Cloudflare connected. Niceproxy is checking DNS and panel HTTPS.");
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
            Connect Cloudflare
          </Text>
          <Text tone="secondary">
            Copy the URL below into Redirect (Callback) URLs when registering a
            Cloudflare OAuth app. Then paste the Client ID and Scope ID here.
          </Text>
          <Text>
            <a
              href="https://dash.cloudflare.com/?to=/:account/oauth-clients"
              target="_blank"
              rel="noreferrer"
            >
              Create OAuth app
            </a>{" "}
            ·{" "}
            <a
              href="https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/"
              target="_blank"
              rel="noreferrer"
            >
              Cloudflare guide
            </a>
          </Text>
          <TextInput
            showIcon={false}
            id="cf-callback"
            label="Redirect URI"
            labelPlacement="inside"
            value={loopback || status.redirectUrl}
            readOnly
          />
          {loopback && status.redirectUrl.startsWith("https://") && (
            <TextInput
              showIcon={false}
              id="cf-public-callback"
              label="Public Redirect URI for domain sign-in"
              labelPlacement="inside"
              value={status.redirectUrl}
              readOnly
            />
          )}
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
            hint="Zone Read, DNS Read, DNS Write. For auto certificate and Full (strict), add Zone Settings Read, SSL and Certificates Edit, Config Settings Read/Write. To refresh access, add offline_access. Separate IDs with spaces or commas."
            required
            disabled={busy}
          />
          <Text tone="secondary">
            Private · response type: code · grant types: authorization_code,
            refresh_token · authentication: none · PKCE: S256. Saving will
            disconnect the current connection.
          </Text>
          {error && <Alert>{error}</Alert>}
          <Stack direction="row" gap={3}>
            <Button
              type="submit"
              loading={busy}
              disabled={!clientId.trim() || !parseScopes(scopes).length}
            >
              Save connection
            </Button>
            <Button
              variant="blank"
              disabled={busy}
              onPress={() => change(() => setSetup(false))}
            >
              Cancel
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
            ? "Connecting…"
            : !status
              ? "Status unavailable"
              : status.connected
                ? "Account connected"
                : status.configured
                  ? "Sign in to your account to manage DNS."
                  : "Connect Cloudflare to manage DNS records."}
        </Text>
      </Stack>
      {callback === "error" && (
        <Alert>
          Failed to connect Cloudflare. Sign in again or check settings.
        </Alert>
      )}
      {callback === "connected" && status?.connected && (
        <Text>Cloudflare connected successfully.</Text>
      )}
      {status?.error && <Alert>{status.error}</Alert>}
      {error && <Alert>{error}</Alert>}
      {notice && (
        <div role="status">
          <Text>{notice}</Text>
        </div>
      )}
      {!status?.connected && authorization && (
        <form onSubmit={finishOAuth}>
          <Stack gap={3}>
            <Text>
              <a href={authorization} target="_blank" rel="noreferrer">
                Open Cloudflare and authorize access
              </a>
            </Text>
            <Text tone="secondary">
              After approving, copy the full localhost URL from the new tab and
              paste it here. This works even if the browser shows that the
              localhost page is unavailable.
            </Text>
            <TextInput
              id="cf-loopback-response"
              label="URL from localhost address bar"
              showIcon={false}
              labelPlacement="inside"
              value={callbackURL}
              onValueChange={setCallbackURL}
              autoComplete="off"
              required
              disabled={busy}
            />
            <Stack direction="row" gap={3}>
              <Button
                type="submit"
                loading={busy}
                disabled={!callbackURL.trim()}
              >
                Complete connection
              </Button>
              <Button
                variant="blank"
                disabled={busy}
                onPress={() => {
                  setAuthorization("");
                  setCallbackURL("");
                  setError("");
                }}
              >
                Cancel
              </Button>
            </Stack>
          </Stack>
        </form>
      )}
      {!status?.connected && !authorization && (
        <Stack direction="row" gap={3}>
          {status && !status.configured && (
            <Button onPress={() => change(() => setSetup(true))}>
              Connect Cloudflare
            </Button>
          )}
          {status?.configured && (
            <Button
              loading={busy}
              onPress={() => void action(() => startOAuth(useLoopback))}
            >
              Sign in with Cloudflare
            </Button>
          )}
          {status?.configured && useLoopback && direct && (
            <Button
              variant="blank"
              disabled={busy}
              onPress={() => void action(() => startOAuth(false))}
            >
              Sign in via panel callback
            </Button>
          )}
          {status?.configured && (
            <Button
              variant="blank"
              disabled={busy}
              onPress={() => change(() => setSetup(true))}
            >
              OAuth settings
            </Button>
          )}
          <Button variant="blank" loading={loading} onPress={() => void load()}>
            Refresh
          </Button>
        </Stack>
      )}
      {status?.connected && (
        <Stack gap={4}>
          {zonesLoading && !zones.length && <Text>Loading zones…</Text>}
          {zonesError && <Alert>{zonesError}</Alert>}
          {!zonesLoading && !zonesError && !zones.length && (
            <Text>No zones available. Check connection permissions.</Text>
          )}
          {!!zones.length && (
            <Select
              popup="overlay"
              id="cf-zone"
              label="Domain zone"
              value={zoneId}
              onValueChange={(value) => {
                ++recordsVersion.current;
                setRecords([]);
                setZoneId(value);
              }}
              options={[
                { value: "", label: "Select a zone" },
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
                Add DNS record
              </Button>
            )}
            <Button
              variant="blank"
              loading={zonesLoading || recordsLoading}
              onPress={() => setRefresh((v) => v + 1)}
            >
              Refresh
            </Button>
          </Stack>
          {recordsLoading && !records.length && (
            <Text>Loading DNS records…</Text>
          )}
          {recordsError && <Alert>{recordsError}</Alert>}
          {zone && !recordsLoading && !recordsError && !records.length && (
            <Text tone="secondary">No DNS records yet.</Text>
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
                      Edit DNS record
                    </Button>
                  ) : (
                    <Text tone="muted">
                      This record type is read-only.
                    </Text>
                  )}
                </Stack>
              </Card>
            ))}
          </Stack>
          <Text tone="muted">
            DNS stores addresses without paths or ports. Cloudflare proxy does
            not serve arbitrary TCP/UDP ports.
          </Text>
        </Stack>
      )}
      {status?.configured && (
        <Stack gap={1}>
          <DrawerDivider label="Connection" />
          <DrawerButton
            label="OAuth settings"
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
                      ? `Account disconnected locally. ${result.warning}`
                      : "Account disconnected.",
                  );
                })
              }
            >
              Disconnect Cloudflare
            </Button>
          )}
          {status.error && (
            <Text>
              <a
                href="https://dash.cloudflare.com/?to=/profile/access-management/authorization"
                target="_blank"
                rel="noreferrer"
              >
                Review and revoke access
              </a>
            </Text>
          )}
          {status.connected && status.expiresAt && (
            <Text tone="muted">Access valid until {status.expiresAt}</Text>
          )}
        </Stack>
      )}
    </Stack>
  );
}
