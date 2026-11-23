import { useEffect } from "react";
import { Button, Card, Stack, Text } from "@alpha/react";

const popupKey = "niceproxy:cloudflare-popup";
const startPage = "/?cloudflare=authorizing#cloudflare";
const panelPage = "/#cloudflare";
export type CloudflareCallback = "connected" | "error";

export type OAuthPopup = {
  navigate(url: string): boolean;
  close(): void;
};

export function openOAuthWindow(onReturn: (result: CloudflareCallback) => void, onTimeout: () => void): OAuthPopup | null {
  if (typeof BroadcastChannel !== "function" || !globalThis.crypto?.randomUUID) return null;
  const popup = window.open("", "_blank", "popup,width=520,height=720");
  if (!popup) return null;

  try {
    const channelName = `${popupKey}:${crypto.randomUUID()}`;
    // The popup keeps its own same-origin storage across the provider visit.
    // Cloudflare can isolate its window, so completion cannot rely on opener.
    popup.sessionStorage.setItem(popupKey, channelName);
    popup.opener = null;
    popup.location.replace(startPage);
    const channel = new BroadcastChannel(channelName);
    // The server allows ten minutes from the start request, which can take
    // up to fifteen seconds.
    const timeout = window.setTimeout(onTimeout, 10 * 60 * 1000 + 15000);
    const close = () => {
      window.clearTimeout(timeout);
      channel.close();
      popup.close();
    };
    channel.onmessage = (event) => {
      if (event.data === "connected" || event.data === "error") onReturn(event.data);
    };
    return {
      navigate(url: string) {
        if (popup.closed) return false;
        popup.location.replace(url);
        return true;
      },
      close,
    };
  } catch {
    popup.close();
    return null;
  }
}

export function CloudflareOAuthWindow({ stage }: {
  stage: CloudflareCallback | "authorizing";
}) {
  useEffect(() => {
    if (stage === "authorizing") return;
    try {
      const channelName = sessionStorage.getItem(popupKey);
      if (!channelName) return;
      sessionStorage.removeItem(popupKey);
      const channel = new BroadcastChannel(channelName);
      channel.postMessage(stage);
      channel.close();
      window.close();
    } catch {
      // Leave the result and the link back to the panel visible.
    }
  }, [stage]);

  return (
    <main className="alpha-ui auth-page">
      <Card>
        <Stack gap={4}>
          <Text as="h1" size="xl" font="heading">Вход через Cloudflare</Text>
          <div role="status">
            <Text>
              {stage === "authorizing" ? "Открываем страницу Cloudflare…"
                : stage === "connected" ? "Доступ подтверждён."
                : "Не удалось подключить Cloudflare. Повторите вход из панели."}
            </Text>
          </div>
          {stage === "authorizing"
            ? <Button variant="simple" onPress={() => window.close()}>Закрыть окно</Button>
            : <Button onPress={() => window.location.replace(panelPage)}>Открыть панель</Button>}
        </Stack>
      </Card>
    </main>
  );
}

export function isCloudflareOAuthWindow() {
  try {
    return sessionStorage.getItem(popupKey) !== null;
  } catch {
    return false;
  }
}
