import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Badge, Button, Card, Icon, Select, Stack, Switch, Text, TextInput } from "@alpha/react";
import { type HttpRoute, Unauthorized } from "./api";
import { openOAuthWindow, type CloudflareCallback, type OAuthPopup } from "./CloudflareOAuth";
import { authorizationURL, cloudflareApi, parseScopes, supportedRecord, type CertificateStatus, type CloudflareStatus, type DNSRecord, type RecordInput, type Zone } from "./cloudflare-api";
const message = (e: unknown) => e instanceof Error ? e.message : "Action failed.";
function Alert({ children }: { children: string }) { return <div role="alert"><Text>{children}</Text></div>; }

function RecordForm({ zone, record, routes, onSaved, onCancel }: {
  zone: Zone; record?: DNSRecord; routes: HttpRoute[]; onSaved: (record: DNSRecord) => void; onCancel: () => void;
}) {
  const [name, setName] = useState(record?.name ?? "");
  const [type, setType] = useState<RecordInput["type"]>(record && supportedRecord(record.type) ? record.type : "A");
  const [content, setContent] = useState(record?.content ?? "");
  const [proxied, setProxied] = useState(record?.proxied ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const suggestions = [...new Set(routes.map(r => r.host.toLowerCase()).filter(host => host === zone.name.toLowerCase() || host.endsWith(`.${zone.name.toLowerCase()}`)))];
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy || !name.trim() || !content.trim()) return;
    setBusy(true); setError("");
    try {
      onSaved(await cloudflareApi.saveRecord(zone.id, { name: name.trim(), type, content: content.trim(), proxied, ttl: record?.ttl ?? 1 }, record?.id));
    } catch (e) { if (!(e instanceof Unauthorized)) setError(message(e)); }
    finally { setBusy(false); }
  }
  return <Card><form onSubmit={submit}><Stack gap={4}>
    <Text as="h3" size="xl" font="heading">{record ? "Edit DNS record" : "New DNS record"}</Text>
    <div className="form-grid">
      <TextInput id="cf-record-name" label="DNS record name" value={name} onValueChange={setName} required disabled={busy} hint={`Full name in zone ${zone.name}`} />
      <Select id="cf-record-type" label="Type" value={type} onValueChange={v => { if (supportedRecord(v)) setType(v); }} disabled={busy} options={["A", "AAAA", "CNAME"].map(value => ({ value, label: value }))} />
      <TextInput id="cf-record-content" label={type === "CNAME" ? "Target domain name" : type === "AAAA" ? "IPv6 address" : "IPv4 address"} value={content} onValueChange={setContent} required disabled={busy} hint="Enter the value without a scheme, path, or port." />
    </div>
    {suggestions.length > 0 && <Select id="cf-route-suggestion" label="Use a name from an HTTP route" value="" onValueChange={v => { if (v) setName(v); }} disabled={busy} options={[{ value: "", label: "Select a name (optional)" }, ...suggestions.map(value => ({ value, label: value }))]} />}
    <Switch id="cf-proxied" label="Cloudflare proxy" checked={proxied} onCheckedChange={setProxied} disabled={busy} hint="Off: DNS only. The standard Cloudflare proxy does not support arbitrary TCP/UDP ports." />
    <Text tone="secondary">DNS records do not contain paths or ports. TTL: {record && record.ttl !== 1 ? `${record.ttl} seconds (preserved)` : "automatic"}.</Text>
    <Text font="mono">Preview: {type} {name.trim() || "name"} → {content.trim() || "value"} · {proxied ? "Cloudflare proxy" : "DNS only"}</Text>
    {error && <Alert>{error}</Alert>}
    <div className="actions">
      <Button type="submit" loading={busy} disabled={busy || !name.trim() || !content.trim()}>{record ? "Save DNS record" : "Create DNS record"}</Button>
      <Button type="button" variant="simple" onPress={onCancel} disabled={busy}>Cancel</Button>
    </div>
  </Stack></form></Card>;
}

export function Cloudflare({ routes = [], callback }: { routes?: HttpRoute[]; callback?: CloudflareCallback }) {
  const [status, setStatus] = useState<CloudflareStatus | null>(null);
  const [certificate, setCertificate] = useState<CertificateStatus | null>(null);
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
  const [zonesLoading, setZonesLoading] = useState(false);
  const [zonesError, setZonesError] = useState("");
  const [recordsLoading, setRecordsLoading] = useState(false);
  const [recordsError, setRecordsError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState<DNSRecord | "new" | null>(null);
  const oauthRef = useRef<OAuthPopup | null>(null);
  const [oauthFailed, setOAuthFailed] = useState(callback === "error");
  const [oauthPending, setOAuthPending] = useState(false);
  const applyStatus = useCallback((s: CloudflareStatus) => {
    setStatus(s); setClientId(s.clientId); setScopes(s.scopes.join(" "));
    setZones([]); setZoneId(""); setRecords([]); setEditor(null);
  }, []);
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [nextStatus, nextCertificate] = await Promise.all([cloudflareApi.status(), cloudflareApi.certificate()]);
      applyStatus(nextStatus);
      setCertificate(nextCertificate);
    }
    catch (e) { if (!(e instanceof Unauthorized)) setError(message(e)); }
    finally { setLoading(false); }
  }, [applyStatus]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => () => {
    oauthRef.current?.close();
    oauthRef.current = null;
  }, []);
  useEffect(() => {
    if (!status?.connected) return;
    let current = true;
    setZonesLoading(true); setZonesError("");
    cloudflareApi.zones().then(data => { if (current) setZones(data.zones); })
      .catch(e => { if (current && !(e instanceof Unauthorized)) setZonesError(message(e)); })
      .finally(() => { if (current) setZonesLoading(false); });
    return () => { current = false; };
  }, [status, refresh]);
  useEffect(() => {
    setRecords([]); setEditor(null); setRecordsError("");
    if (!status?.connected || !zoneId) { setRecordsLoading(false); return; }
    let current = true;
    setRecordsLoading(true);
    cloudflareApi.records(zoneId).then(data => { if (current) setRecords(data.records); })
      .catch(e => { if (current && !(e instanceof Unauthorized)) setRecordsError(message(e)); })
      .finally(() => { if (current) setRecordsLoading(false); });
    return () => { current = false; };
  }, [zoneId, status, refresh]);
  async function action(run: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setNotice(""); setOAuthFailed(false);
    try { await run(); }
    catch (e) { if (!(e instanceof Unauthorized)) setError(message(e)); }
    finally { setBusy(false); }
  }
  function saveSettings(e: FormEvent) {
    e.preventDefault();
    if (!clientId.trim() || !parseScopes(scopes).length || !status?.redirectUrl) return;
    void action(async () => {
      applyStatus(await cloudflareApi.settings(clientId.trim(), parseScopes(scopes)));
      setSetup(false);
    });
  }
  async function copyCallback() {
    if (!status?.redirectUrl) return;
    try {
      await navigator.clipboard.writeText(status.redirectUrl);
    } catch {
      let copied = false;
      try {
        const input = document.createElement("textarea");
        input.value = status.redirectUrl;
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.focus(); input.select();
        copied = document.execCommand("copy");
        input.remove();
      } catch {
        // Fall through to the manual-copy message.
      }
      if (!copied) {
        setError("Could not copy the callback. Select the URL and copy it manually.");
        return;
      }
    }
    setNotice("Callback URL copied.");
  }
  function closeOAuth() {
    oauthRef.current?.close();
    oauthRef.current = null;
    setOAuthPending(false);
  }
  async function beginOAuth(inCurrentTab = false) {
    closeOAuth();
    setSetup(false);
    const oauth = inCurrentTab ? null : openOAuthWindow(
      (result) => {
        closeOAuth();
        setOAuthFailed(result === "error");
        void load();
      },
      () => {
        closeOAuth();
        setNotice("The request timed out. Try signing in again.");
      },
    );
    oauthRef.current = oauth;
    try {
      const result = await cloudflareApi.connect();
      const url = authorizationURL(result.url);
      if (oauth) {
        if (oauthRef.current !== oauth) return;
        if (!oauth.navigate(url)) {
          closeOAuth();
          setNotice("The Cloudflare window was closed. Try signing in again.");
          return;
        }
        setOAuthPending(true);
      } else {
        window.location.assign(url);
      }
    } catch (e) {
      closeOAuth();
      throw e;
    }
  }
  const zone = zones.find(z => z.id === zoneId);
  return <div className="cloudflare-panel"><Stack gap={4}>
    <Card><Stack gap={4}>
      <div className="oauth-heading">
        <Icon name="shield" />
        <div>
          <Text as="h2" size="xl" font="heading">Cloudflare access</Text>
          <Text tone="secondary">Connect Cloudflare to manage DNS in Niceproxy.</Text>
        </div>
      </div>
      <div className="status" role="status"><Badge value={loading ? "Loading…" : !status ? "Load error" : status.connected ? "Connected" : oauthPending ? "Waiting for approval" : status.configured ? "Ready to sign in" : "Setup required"} /></div>
      {oauthFailed && !loading && !status?.error && <Alert>Cloudflare connection failed. Try again or check the app settings.</Alert>}
      {status?.error && !oauthPending && <><Alert>{status.error}</Alert><Text><a href="https://dash.cloudflare.com/?to=/profile/access-management/authorization" target="_blank" rel="noreferrer">Review and revoke Cloudflare access</a></Text></>}
      {error && <Alert>{error}</Alert>}
      {notice && <div role="status"><Text>{notice}</Text></div>}
      {certificate && <Text tone="secondary">Origin certificate {certificate.domain ? `for ${certificate.domain}: ` : ""}{certificate.state === "issued" ? `issued until ${certificate.expiresAt ? new Date(certificate.expiresAt).toLocaleString("en-US") : "unknown date"}` : certificate.state === "pending" ? "waiting for Caddy ACME issuance" : certificate.state === "not_configured" ? "not configured" : certificate.error || certificate.state}.</Text>}
      {!status?.connected && status?.configured && <>
        <Text tone="secondary">{oauthPending
          ? "Approve access in the Cloudflare window. The panel will update automatically."
          : "Sign in to Cloudflare and approve access to the required zones."}</Text>
        <div className="actions">
          {oauthPending ? <>
            <Button onPress={() => void action(() => beginOAuth(true))} disabled={busy || loading}>Sign in in this tab</Button>
            <Button variant="simple" onPress={() => { closeOAuth(); void load(); }} disabled={busy || loading}>Stop waiting</Button>
          </> : <>
            <Button disabled={busy || loading} loading={busy} onPress={() => void action(beginOAuth)}><Icon name="external" />Sign in with Cloudflare</Button>
            <Button variant="simple" onPress={() => void load()} loading={loading} disabled={loading || busy}>Refresh status</Button>
          </>}
        </div>
      </>}
      {status?.connected && <div className="oauth-connected">
        <div><Stack gap={1}>
          <Text weight="medium">Cloudflare account connected</Text>
          {status.expiresAt && <Text tone="secondary">Token expires {new Date(status.expiresAt).toLocaleString("en-US")}.</Text>}
        </Stack></div>
        <div className="actions">
          <Button variant="simple" onPress={() => void load()} loading={loading} disabled={loading || busy || editor !== null}>Refresh status</Button>
          <Button variant="simple" disabled={busy || loading || editor !== null} onPress={() => void action(async () => {
            const result = await cloudflareApi.disconnect();
            applyStatus({ ...status, connected: false, expiresAt: undefined, error: undefined });
            setNotice(result.warning ? `Account disconnected locally. ${result.warning}` : "Account disconnected.");
          })}>Disconnect account</Button>
        </div>
      </div>}
      {status && !status.configured && <Text tone="secondary">Register a Cloudflare OAuth app and save its settings below to sign in.</Text>}
      {!status && !loading && <div className="actions"><Button onPress={() => void load()}>Retry loading</Button></div>}
    </Stack></Card>
    {status && <Card><Stack gap={4}>
      <div className="section-heading">
        <div>
          <Text as="h2" size="xl" font="heading">OAuth app setup</Text>
          <Text tone="secondary">One-time setup for this Niceproxy instance.</Text>
        </div>
        {status.configured && <Button variant="simple" onPress={() => setSetup(!setup)} disabled={busy || loading || oauthPending || editor !== null}>{setup ? "Hide settings" : "Edit settings"}</Button>}
      </div>
      {(setup || !status.configured) && <form onSubmit={saveSettings}><Stack gap={4}>
        <Text><a href="https://dash.cloudflare.com/?to=/:account/oauth-clients" target="_blank" rel="noreferrer">Create a Cloudflare OAuth client</a> and use the Redirect URI shown below. Private visibility is enough for a personal instance.</Text>
        <Text tone="secondary">Use Response Type Code, Grant type Authorization Code, and Token Authentication Method None. Grant Zone Read, DNS Read, DNS Write, and offline_access for the required zones.</Text>
        {status.redirectUrl
          ? <div className="callback-field"><TextInput id="cf-callback" label="Redirect URI" value={status.redirectUrl} readOnly /><Button type="button" variant="simple" onPress={() => void copyCallback()}>Copy</Button></div>
          : <Alert>Redirect URI is not configured. For a local panel use http://127.0.0.1:9080/api/cloudflare/callback. For a public domain, set NICEPROXY_DOMAIN and restart niceproxy.</Alert>}
        <div className="form-grid">
          <TextInput id="cf-client-id" label="Public client ID" value={clientId} onValueChange={setClientId} required disabled={busy} />
          <TextInput id="cf-scopes" label="Scope ID" value={scopes} onValueChange={setScopes} hint="IDs from the Cloudflare dashboard, separated by spaces or commas." required disabled={busy} />
        </div>
        {status.connected && <Text tone="secondary">Saving new settings disconnects the current account.</Text>}
        <div className="actions">
          <Button type="submit" loading={busy} disabled={busy || !clientId.trim() || !parseScopes(scopes).length || !status.redirectUrl}>Save settings</Button>
          <Text><a href="https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/" target="_blank" rel="noreferrer">Cloudflare guide</a></Text>
        </div>
      </Stack></form>}
    </Stack></Card>}
    {status?.connected && <>
      <Card><Stack gap={4}>
        <Text as="h2" size="xl" font="heading">Zones and DNS records</Text>
        <Text tone="secondary">DNS records do not contain paths or ports. The standard Cloudflare proxy does not support arbitrary TCP/UDP.</Text>
        <div className="actions"><Button variant="simple" onPress={() => setRefresh(v => v + 1)} disabled={zonesLoading || recordsLoading || editor !== null}>Refresh zones and records</Button></div>
        {zonesLoading && <Text>Loading zones…</Text>}
        {zonesError && <Alert>{zonesError}</Alert>}
        {!zonesLoading && !zonesError && zones.length === 0 && <Text>No zones available. Check the OAuth app permissions.</Text>}
        {zones.length > 0 && <Select id="cf-zone" label="Zone · account · status" value={zoneId} onValueChange={setZoneId} disabled={editor !== null || zonesLoading} options={[{ value: "", label: "Select a zone" }, ...zones.map(z => ({ value: z.id, label: `${z.name} · ${z.account.name} · ${z.status}` }))]} />}
        {zone && <Text>Account: {zone.account.name} · {zone.name}</Text>}
        {recordsLoading && <Text>Loading DNS records…</Text>}
        {recordsError && <Alert>{recordsError}</Alert>}
        {zone && !editor && <div className="actions"><Button onPress={() => setEditor("new")} disabled={recordsLoading}>Add DNS record</Button></div>}
      </Stack></Card>
      {zone && editor && <RecordForm key={`${zone.id}:${editor === "new" ? "new" : editor.id}`} zone={zone} record={editor === "new" ? undefined : editor} routes={routes} onCancel={() => setEditor(null)} onSaved={saved => {
        setRecords(current => current.some(r => r.id === saved.id) ? current.map(r => r.id === saved.id ? saved : r) : [...current, saved]); setEditor(null);
      }} />}
      {zone && !recordsLoading && !recordsError && records.length === 0 && <Card><Text>No DNS records yet.</Text></Card>}
      {records.map(record => <Card key={record.id}><div className="route-row">
        <div className="route-mapping"><Stack gap={2}><Text font="mono">{record.type} {record.name} → {record.content}</Text><Text tone="secondary">{record.proxied ? "Cloudflare proxy" : "DNS only"} · TTL {record.ttl === 1 ? "Auto" : record.ttl}</Text></Stack></div>
        {supportedRecord(record.type) && <div className="actions"><Button variant="simple" onPress={() => setEditor(record)} disabled={editor !== null}>Edit</Button></div>}
      </div></Card>)}
    </>}
  </Stack></div>;
}
