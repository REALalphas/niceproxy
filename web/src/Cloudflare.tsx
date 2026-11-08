import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Badge, Button, Card, Select, Stack, Switch, Text, TextInput } from "@alpha/react";
import { type HttpRoute, Unauthorized } from "./api";
import { authorizationURL, cloudflareApi, parseScopes, supportedRecord, type CloudflareStatus, type DNSRecord, type RecordInput, type Zone } from "./cloudflare-api";
const message = (e: unknown) => e instanceof Error ? e.message : "Не удалось выполнить действие.";
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
    <Text as="h3" size="xl" font="heading">{record ? "Изменить DNS-запись" : "Новая DNS-запись"}</Text>
    <div className="form-grid">
      <TextInput id="cf-record-name" label="Имя DNS-записи" value={name} onValueChange={setName} required disabled={busy} hint={`Полное имя в зоне ${zone.name}`} />
      <Select id="cf-record-type" label="Тип" value={type} onValueChange={v => { if (supportedRecord(v)) setType(v); }} disabled={busy} options={["A", "AAAA", "CNAME"].map(value => ({ value, label: value }))} />
      <TextInput id="cf-record-content" label={type === "CNAME" ? "Целевое доменное имя" : type === "AAAA" ? "IPv6-адрес" : "IPv4-адрес"} value={content} onValueChange={setContent} required disabled={busy} hint="Введите значение вручную, без схемы, пути и порта." />
    </div>
    {suggestions.length > 0 && <Select id="cf-route-suggestion" label="Подставить имя из HTTP-маршрута" value="" onValueChange={v => { if (v) setName(v); }} disabled={busy} options={[{ value: "", label: "Выберите имя (необязательно)" }, ...suggestions.map(value => ({ value, label: value }))]} />}
    <Switch id="cf-proxied" label="Cloudflare proxy" checked={proxied} onCheckedChange={setProxied} disabled={busy} hint="Выключено: DNS only. Обычный прокси Cloudflare не обслуживает произвольные TCP/UDP-порты." />
    <Text tone="secondary">DNS не содержит путей и портов. TTL: {record && record.ttl !== 1 ? `${record.ttl} секунд (сохраняется)` : "автоматически"}.</Text>
    <Text font="mono">Предпросмотр: {type} {name.trim() || "имя"} → {content.trim() || "значение"} · {proxied ? "Cloudflare proxy" : "DNS only"}</Text>
    {error && <Alert>{error}</Alert>}
    <div className="actions">
      <Button type="submit" loading={busy} disabled={busy || !name.trim() || !content.trim()}>{record ? "Сохранить DNS-запись" : "Создать DNS-запись"}</Button>
      <Button type="button" variant="simple" onPress={onCancel} disabled={busy}>Отмена</Button>
    </div>
  </Stack></form></Card>;
}

export function Cloudflare({ routes = [], callback }: { routes?: HttpRoute[]; callback?: string }) {
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
  const [zonesLoading, setZonesLoading] = useState(false);
  const [zonesError, setZonesError] = useState("");
  const [recordsLoading, setRecordsLoading] = useState(false);
  const [recordsError, setRecordsError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState<DNSRecord | "new" | null>(null);
  const applyStatus = useCallback((s: CloudflareStatus) => {
    setStatus(s); setClientId(s.clientId); setScopes(s.scopes.join(" "));
    setZones([]); setZoneId(""); setRecords([]); setEditor(null);
  }, []);
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { applyStatus(await cloudflareApi.status()); }
    catch (e) { if (!(e instanceof Unauthorized)) setError(message(e)); }
    finally { setLoading(false); }
  }, [applyStatus]);
  useEffect(() => { void load(); }, [load]);
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
    setBusy(true); setError(""); setNotice("");
    try { await run(); }
    catch (e) { if (!(e instanceof Unauthorized)) setError(message(e)); }
    finally { setBusy(false); }
  }
  function saveSettings(e: FormEvent) {
    e.preventDefault();
    if (!clientId.trim() || !parseScopes(scopes).length) return;
    void action(async () => {
      applyStatus(await cloudflareApi.settings(clientId.trim(), parseScopes(scopes)));
      setSetup(false); setNotice("Настройки сохранены. Войдите в аккаунт Cloudflare заново.");
    });
  }
  const zone = zones.find(z => z.id === zoneId);
  return <div className="cloudflare-panel"><Stack gap={4}>
    <Card><Stack gap={4}>
      <Text as="h2" size="xl" font="heading">Аккаунт Cloudflare</Text>
      <Text tone="secondary">Интеграция для управления DNS. Вход администратора Niceproxy по паролю остаётся отдельным.</Text>
      <div className="status" role="status"><Badge value={loading ? "Загрузка…" : !status ? "Ошибка загрузки" : status.connected ? "Подключено" : status.configured ? "Не подключено" : "Требуется настройка"} /></div>
      {callback === "error" && <Alert>Не удалось подключить Cloudflare. Повторите вход или проверьте настройки приложения.</Alert>}
      {callback === "connected" && status?.connected && <Text>Аккаунт Cloudflare успешно подключён.</Text>}
      {status?.error && <><Alert>{status.error}</Alert><Text><a href="https://dash.cloudflare.com/?to=/profile/access-management/authorization" target="_blank" rel="noreferrer">Проверить и отозвать доступ в Cloudflare</a></Text></>}
      {error && <Alert>{error}</Alert>}
      {notice && <Text>{notice}</Text>}
      {status?.connected && status.expiresAt && <Text>Срок действия текущего разрешения: {status.expiresAt}</Text>}
      <div className="actions">
        <Button variant="simple" onPress={() => void load()} loading={loading} disabled={loading || busy || editor !== null}>Обновить состояние</Button>
        {status?.configured && !status.connected && <Button disabled={busy || loading} loading={busy} onPress={() => void action(async () => { const result = await cloudflareApi.connect(); window.location.assign(authorizationURL(result.url)); })}>Войти через Cloudflare</Button>}
        {status?.connected && <Button variant="simple" disabled={busy || loading || editor !== null} onPress={() => void action(async () => {
          const result = await cloudflareApi.disconnect();
          applyStatus({ ...status, connected: false, expiresAt: undefined, error: undefined });
          setNotice(result.warning ? `Аккаунт отключён локально. ${result.warning}` : "Аккаунт отключён.");
        })}>Отключить аккаунт</Button>}
      </div>
    </Stack></Card>
    {status && <Card><Stack gap={4}>
      <Button variant="simple" onPress={() => setSetup(!setup)} disabled={busy || loading || editor !== null}>{setup ? "Скрыть настройку OAuth" : status.configured ? "Изменить настройку OAuth" : "Настроить OAuth-приложение"}</Button>
      {setup && <form onSubmit={saveSettings}><Stack gap={4}>
        <Text>Администратор один раз регистрирует OAuth-приложение Cloudflare с PKCE. Для личной установки подходит видимость Private. Затем пользователям нужна только кнопка «Войти через Cloudflare».</Text>
        <Text><a href="https://dash.cloudflare.com/?to=/:account/oauth-clients" target="_blank" rel="noreferrer">Регистрация приложения в Cloudflare</a> · <a href="https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/" target="_blank" rel="noreferrer">Официальная инструкция</a></Text>
        <Text>Настройки регистрации: response type — code; grant types — authorization_code и refresh_token; authentication — none; PKCE — S256. Минимальные разрешения: Zone Read, DNS Read, DNS Write; offline_access — для обновления доступа.</Text>
        <Text>Скопируйте scope ID из панели Cloudflare. Укажите доступ к нужным зонам. Изменение настроек отключит текущий аккаунт.</Text>
        <TextInput id="cf-callback" label="Callback URL / Redirect URI" value={status.redirectUrl} readOnly />
        <TextInput id="cf-client-id" label="Публичный OAuth Client ID" value={clientId} onValueChange={setClientId} required disabled={busy} />
        <TextInput id="cf-scopes" label="Scope ID" value={scopes} onValueChange={setScopes} hint="ID из панели Cloudflare, через пробел или запятую." required disabled={busy} />
        <div className="actions"><Button type="submit" loading={busy} disabled={busy || !clientId.trim() || !parseScopes(scopes).length}>Сохранить настройки</Button></div>
      </Stack></form>}
    </Stack></Card>}
    {status?.connected && <>
      <Card><Stack gap={4}>
        <Text as="h2" size="xl" font="heading">Зоны и DNS-записи</Text>
        <Text tone="secondary">DNS не содержит путей и портов. Обычный Cloudflare proxy не покрывает произвольный TCP/UDP.</Text>
        <div className="actions"><Button variant="simple" onPress={() => setRefresh(v => v + 1)} disabled={zonesLoading || recordsLoading || editor !== null}>Обновить зоны и записи</Button></div>
        {zonesLoading && <Text>Загрузка зон…</Text>}
        {zonesError && <Alert>{zonesError}</Alert>}
        {!zonesLoading && !zonesError && zones.length === 0 && <Text>Нет доступных зон. Проверьте разрешения OAuth-приложения.</Text>}
        {zones.length > 0 && <Select id="cf-zone" label="Зона · аккаунт · состояние" value={zoneId} onValueChange={setZoneId} disabled={editor !== null || zonesLoading} options={[{ value: "", label: "Выберите зону" }, ...zones.map(z => ({ value: z.id, label: `${z.name} · ${z.account.name} · ${z.status}` }))]} />}
        {zone && <Text>Аккаунт: {zone.account.name} · {zone.name}</Text>}
        {recordsLoading && <Text>Загрузка DNS-записей…</Text>}
        {recordsError && <Alert>{recordsError}</Alert>}
        {zone && !editor && <div className="actions"><Button onPress={() => setEditor("new")} disabled={recordsLoading}>Добавить DNS-запись</Button></div>}
      </Stack></Card>
      {zone && editor && <RecordForm key={`${zone.id}:${editor === "new" ? "new" : editor.id}`} zone={zone} record={editor === "new" ? undefined : editor} routes={routes} onCancel={() => setEditor(null)} onSaved={saved => {
        setRecords(current => current.some(r => r.id === saved.id) ? current.map(r => r.id === saved.id ? saved : r) : [...current, saved]); setEditor(null);
      }} />}
      {zone && !recordsLoading && !recordsError && records.length === 0 && <Card><Text>DNS-записей пока нет.</Text></Card>}
      {records.map(record => <Card key={record.id}><div className="route-row">
        <div className="route-mapping"><Stack gap={2}><Text font="mono">{record.type} {record.name} → {record.content}</Text><Text tone="secondary">{record.proxied ? "Cloudflare proxy" : "DNS only"} · TTL {record.ttl === 1 ? "Auto" : record.ttl}</Text></Stack></div>
        {supportedRecord(record.type) && <div className="actions"><Button variant="simple" onPress={() => setEditor(record)} disabled={editor !== null}>Изменить</Button></div>}
      </div></Card>)}
    </>}
  </Stack></div>;
}
