import { useEffect, useState } from "react";
import { Button, Select, Stack, Text } from "@alpha/react";
import { Unauthorized } from "./api";
import { cloudflareApi, domainSuggestions, supportedRecord, zoneForDomain, type Zone } from "./cloudflare-api";

const message = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось загрузить домены Cloudflare.";

function CloudflareZoneDomains({ zone, host, panelDomain, onPick, disabled }: {
  zone: Zone;
  host: string;
  panelDomain: string;
  onPick: (host: string) => void;
  disabled: boolean;
}) {
  const [names, setNames] = useState<string[]>();
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    cloudflareApi.records(zone.id).then(({ records }) => {
      if (active) setNames(records.filter(({ type }) => supportedRecord(type)).map(({ name }) => name));
    }).catch((e) => {
      if (active && !(e instanceof Unauthorized)) setError(message(e));
    });
    return () => { active = false; };
  }, [zone.id]);
  const suggestions = domainSuggestions(zone.name, [zone.name, ...(names ?? [])])
    .filter((name) => name !== panelDomain);
  return (
    <>
      {suggestions.length > 0 && (
        <Select
          popup="overlay"
          id="http-cloudflare-domain"
          label="Подставить домен из Cloudflare"
          value={suggestions.includes(host) ? host : ""}
          onValueChange={(value) => { if (value) onPick(value); }}
          options={[
            { value: "", label: "Выберите имя (необязательно)" },
            ...suggestions.map((value) => ({ value, label: value })),
          ]}
          disabled={disabled}
        />
      )}
      {!names && !error && <Text tone="secondary">Загрузка DNS-записей…</Text>}
      {error && <div role="alert"><Text>{error}</Text></div>}
    </>
  );
}

export function CloudflareRouteDomains({ host, panelDomain, onPick, disabled }: {
  host: string;
  panelDomain: string;
  onPick: (host: string) => void;
  disabled: boolean;
}) {
  const [show, setShow] = useState(false);
  const [zones, setZones] = useState<Zone[]>([]);
  const [zoneId, setZoneId] = useState("");
  const [loading, setLoading] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");

  async function open() {
    setShow(true);
    setLoading(true);
    try {
      const status = await cloudflareApi.status();
      setConnected(status.connected);
      if (!status.connected) return;
      const { zones } = await cloudflareApi.zones();
      setZones(zones);
      setZoneId(zoneForDomain(zones, host)?.id ?? (zones.length === 1 ? zones[0].id : ""));
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(message(e));
    } finally {
      setLoading(false);
    }
  }

  if (!show) return (
    <Button type="button" variant="simple" disabled={disabled} onPress={() => void open()}>
      Подобрать домен в Cloudflare
    </Button>
  );

  const zone = zones.find(({ id }) => id === zoneId);
  return (
    <Stack gap={3}>
      {loading && <Text tone="secondary">Загрузка зон…</Text>}
      {error && <div role="alert"><Text>{error}</Text></div>}
      {!loading && !error && !connected && (
        <Text>Для подсказок <a href="#settings/cloudflare">подключите Cloudflare</a>.</Text>
      )}
      {!loading && !error && connected && !zones.length && (
        <Text>Нет доступных зон. Проверьте аккаунт и доступ к зонам в разрешении Cloudflare.</Text>
      )}
      {zones.length > 0 && (
        <Select
          popup="overlay"
          id="http-cloudflare-zone"
          label="Зона Cloudflare"
          value={zoneId}
          onValueChange={setZoneId}
          options={[
            { value: "", label: "Выберите зону" },
            ...zones.map(({ id, name, account }) => ({ value: id, label: `${name} · ${account.name}` })),
          ]}
          disabled={disabled}
        />
      )}
      {zone && <CloudflareZoneDomains key={zone.id} zone={zone} host={host}
        panelDomain={panelDomain} onPick={onPick} disabled={disabled} />}
    </Stack>
  );
}
