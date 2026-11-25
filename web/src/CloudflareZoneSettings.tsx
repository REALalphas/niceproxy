import { useEffect, useState } from "react";
import { Button, Card, Select, Stack, Text } from "@alpha/react";
import { Unauthorized } from "./api";
import { cloudflareApi, type ZoneSetting, type ZoneSettingID } from "./cloudflare-api";

const onOff = [
  { value: "on", label: "Включено" },
  { value: "off", label: "Выключено" },
];
const settings = [
  {
    id: "ssl",
    label: "Режим SSL/TLS",
    options: [
      { value: "off", label: "Off" },
      { value: "flexible", label: "Flexible" },
      { value: "full", label: "Full" },
      { value: "strict", label: "Full (strict)" },
      { value: "origin_pull", label: "Strict (SSL-Only Origin Pull)" },
    ],
  },
  { id: "always_use_https", label: "Always Use HTTPS", options: onOff },
  { id: "automatic_https_rewrites", label: "Automatic HTTPS Rewrites", options: onOff },
] satisfies { id: ZoneSettingID; label: string; options: typeof onOff }[];

const message = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось получить настройки Cloudflare.";

function SettingEditor({ zoneId, setting, onSaved }: {
  zoneId: string;
  setting: (typeof settings)[number];
  onSaved: () => void;
}) {
  const { id, label, options } = setting;
  const [current, setCurrent] = useState<ZoneSetting>();
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    let active = true;
    cloudflareApi.zoneSetting(zoneId, id).then((result) => {
      if (!active) return;
      setCurrent(result);
      setDraft(result.value);
    }).catch((e) => {
      if (active && !(e instanceof Unauthorized)) setError(message(e));
    });
    return () => { active = false; };
  }, [zoneId, id]);

  async function save() {
    if (busy || !current?.editable || draft === current.value) return;
    setBusy(true);
    setSaved(false);
    setError("");
    try {
      const result = await cloudflareApi.saveZoneSetting(zoneId, id, draft);
      setCurrent(result);
      setDraft(result.value);
      setSaved(true);
      onSaved();
    } catch (e) {
      if (!(e instanceof Unauthorized)) setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  const currentLabel = current && (options.find(({ value }) => value === current.value)?.label ?? current.value);
  const choices = current && !options.some(({ value }) => value === current.value)
    ? [{ value: current.value, label: current.value }, ...options]
    : options;
  return (
    <Card>
      <Stack gap={3}>
        <Text as="h3" font="heading">{label}</Text>
        {!current && !error && <Text tone="secondary">Загрузка…</Text>}
        {current && <Text tone="secondary">Текущее значение · {currentLabel}</Text>}
        {current?.editable && (
          <>
            <Select
              popup="overlay"
              id={`cf-setting-${id}`}
              label={`Новое значение · ${label}`}
              value={draft}
              onValueChange={(value) => {
                setDraft(value);
                setSaved(false);
              }}
              options={choices}
              disabled={busy}
            />
            <Button variant="simple" onPress={() => void save()}
              loading={busy} disabled={draft === current.value}>
              Сохранить для всей зоны
            </Button>
          </>
        )}
        {current && !current.editable && (
          <Text tone="secondary">Cloudflare разрешает только просмотр для этой зоны.</Text>
        )}
        {saved && <div role="status"><Text>Cloudflare подтвердил изменение.</Text></div>}
        {error && <div role="alert"><Text>{error}</Text></div>}
      </Stack>
    </Card>
  );
}

export function CloudflareZoneSettings({ zoneId, onSaved }: { zoneId: string; onSaved: () => void }) {
  return (
    <Stack gap={3}>
      <Text as="h2" font="heading">Настройки зоны</Text>
      <Text tone="secondary">
        Изменения действуют на всю выбранную зону. Для редактирования нужны права Zone Settings Write (Edit).
      </Text>
      {settings.map((setting) => (
        <SettingEditor key={setting.id} zoneId={zoneId} setting={setting} onSaved={onSaved} />
      ))}
    </Stack>
  );
}
