import { useEffect, useState } from "react";

export const locales = [{ code: "en", label: "English" }] as const;
export type Locale = (typeof locales)[number]["code"];
type Values = Record<string, string>;

const en: Values = {
  "sections.routes": "Routes",
  "sections.overview": "Service",
  "sections.settings": "Settings",
  "sections.antiDDoS": "DDoS protection",
  "sections.cloudflare": "Cloudflare DNS",
  "sections.account": "Panel access",
  "nav.back": "Back",
  "nav.refresh": "Refresh",
  "nav.cancel": "Cancel",
  "nav.edit": "Edit",
  "nav.delete": "Delete",
  "nav.retry": "Retry",
  "lang.label": "Language",
  "lang.auto": "Browser default",
  "auth.accountLabel": "Admin account",
  "auth.loginTitle": "Sign in to Niceproxy",
  "auth.setupTitle": "Initial setup",
  "auth.loginHint": "Enter administrator password.",
  "auth.setupHint": "Create an administrator password: 12 to 72 bytes.",
  "auth.password": "Password",
  "auth.signIn": "Sign in",
  "auth.savePassword": "Save password",
  "auth.signedIn": "Signed in as administrator.",
  "auth.signOut": "Sign out",
  "routes.add": "Add route",
  "routes.open": "Open route",
  "routes.newHttp": "New HTTP/HTTPS route",
  "routes.newDirect": "New TCP/UDP rule",
  "routes.editTitle": "Edit route",
  "routes.deleteTitle": "Delete route",
  "routes.countOf": "{count} of {total}",
  "routes.protocol": "Protocol",
  "routes.allProtocols": "All protocols",
  "routes.domain": "Domain",
  "routes.path": "Path",
  "routes.service": "Service",
  "routes.serviceUrl": "Service URL",
  "routes.enabled": "Route enabled",
  "routes.save": "Save route",
  "routes.create": "Create route",
  "routes.status.disabled": "Disabled",
  "routes.status.healthy": "Applied",
  "routes.status.waitingAcme": "Waiting for certificate",
  "routes.status.waitingDns": "Waiting for DNS",
  "routes.status.invalidCertificate": "Invalid certificate",
  "routes.status.error": "Apply error",
  "routes.status.unconfirmed": "Unconfirmed",
  "routes.emptyFiltered": "No routes of this type",
  "routes.empty": "Connect your first service",
  "routes.emptyHint": "Choose another protocol or add a route.",
  "routes.emptyFirstHint":
    "HTTP/HTTPS uses a domain and path. TCP/UDP uses a port.",
  "routes.notFound": "Route not found.",
  "routes.deleteConfirm":
    "Delete this route? New connections will no longer be served.",
  "route.incoming": "Incoming address",
  "route.publicPorts": "Public ports",
  "route.connection": "Connection",
  "route.connectionPoint": "Connection point",
  "route.incomingHint": "Enter the incoming address",
  "route.rules": "Rules",
  "route.serviceHint": "Enter the service address",
  "route.diagram": "Route diagram",
  "route.domainPathMatch": "Domain and path match",
  "route.directForward": "Direct forwarding",
  "route.publicPortsAuto": "Public ports will be selected automatically",
  "route.incomingPort": "incoming port",
  "route.httpsAccess": "HTTPS access",
  "route.tlsHint": "Use the same mode for all paths on one domain.",
  "route.tlsAuto": "Automatic certificate",
  "route.tlsInternal": "Local certificate",
  "route.tlsOff": "No HTTPS (HTTP)",
  "route.serverIp": "Server IP",
  "route.port": "Port",
  "route.listenHostHint": "Leave the IP empty to accept on all interfaces.",
  "route.unavailableFeatures":
    "Access filters, DDoS protection, and panel login (Secured Route) are unavailable in route settings.",
  "route.proxying": "Proxying",
  "route.serviceUrlHint":
    "Enter an HTTP(S) service address. You can omit the port when it is standard.",
  "route.stripPrefix": "Remove path prefix",
  "route.stripPrefixHint":
    "For example, /api/users → /users. Query parameters are preserved.",
  "route.serverIpOrDomain": "IP or domain",
  "route.targetPortHint":
    "When the service port is empty, the incoming port is used.",
  "route.pathHint":
    "For example, / matches all paths, while /api matches /api and /api/users.",
  "routeErrors.targetAddress":
    "Enter an HTTP(S), TCP, or UDP service address without a path, parameters, or password.",
  "routeErrors.targetPort": "Enter the service port for TCP/UDP.",
  "routeErrors.domain": "Enter a domain.",
  "routeErrors.path":
    "Enter a literal path starting with / without whitespace, control characters, //, ., .., parameters, or patterns (up to 2048 bytes).",
  "routeErrors.listenHost": "Enter an interface IP or leave the field empty.",
  "routeErrors.listenPort": "Enter an incoming port from 1 to 65535.",
  "routeErrors.targetHost": "Enter the service IP address or domain.",
  "routeErrors.targetHostFormat":
    "Enter an IP address or domain without a scheme, path, or port.",
  "routeErrors.targetPortOptional":
    "Enter a port from 1 to 65535 or leave the field empty.",
  "settings.antiDDoSSub": "Protection policies and filtering status",
  "settings.cloudflareSub": "Account connection and DNS records",
  "settings.accountSub": "Administrator session",
  "overview.applied": "Configuration applied",
  "overview.partial": "Configuration partially applied",
  "overview.unavailable": "Status unavailable",
  "overview.reapply": "Reapply",
  "overview.invalidCertificate": "Invalid panel certificate", "overview.waitingCertificate": "Waiting for public certificate", "overview.applyError": "Apply error", "overview.saved": "Saved:", "overview.appliedRevision": "applied:", "overview.partialShort": "partial", "overview.unknown": "unknown", "overview.webAvailable": "Web server available", "overview.webUnavailable": "Web server unavailable", "overview.webUnknown": "Web server status unknown", "overview.reapplyState": "Reapply", "overview.refreshState": "Refresh status", "overview.routing": "Routing", "overview.saveWarning": "Saving changes does not mean they were applied successfully.", "route.directBusy": "direct forwarding", "route.webAccess": "web access",
  "cloudflare.connect": "Connect Cloudflare",
  "cloudflare.signIn": "Sign in with Cloudflare",
  "cloudflare.disconnect": "Disconnect Cloudflare",
  "cloudflare.oauthSettings": "OAuth settings",
  "cloudflare.connected": "Account connected",
  "cloudflare.zone": "Domain zone",
  "cloudflare.selectZone": "Select zone",
  "cloudflare.addRecord": "Add DNS record",
  "cloudflare.editRecord": "Edit DNS record",
  "cloudflare.zoneHint": "Full name in zone {name}",
  "cloudflare.recordsCount": "DNS records: {count}",
  "cloudflare.newRecord": "New DNS record",
  "cloudflare.recordName": "DNS record name",
  "cloudflare.targetDomain": "Target domain name",
  "cloudflare.routeSuggestion": "Use name from an HTTP route",
  "cloudflare.selectNameOptional": "Select a name (optional)",
  "cloudflare.proxyHint":
    "Disabled: DNS only. The standard Cloudflare proxy does not serve arbitrary TCP/UDP ports.",
  "cloudflare.dnsNoPaths": "DNS does not contain paths or ports.",
  "cloudflare.ttlSaved": "{ttl} seconds (saved)",
  "cloudflare.auto": "automatic",
  "cloudflare.preview": "Preview",
  "cloudflare.name": "name",
  "cloudflare.value": "value",
  "cloudflare.saveRecord": "Save DNS record",
  "cloudflare.createRecord": "Create DNS record",
  "cloudflare.saveConnection": "Save connection",
  "cloudflare.connecting": "Connecting…",
  "cloudflare.signInHint": "Sign in to manage DNS.",
  "cloudflare.connectHint": "Connect Cloudflare to manage DNS records.",
  "cloudflare.connectError":
    "Failed to connect Cloudflare. Sign in again or check settings.",
  "cloudflare.connectedSuccess": "Cloudflare connected successfully.",
  "cloudflare.openAndAuthorize": "Open Cloudflare and authorize access",
  "cloudflare.callbackHint":
    "After confirmation, copy the full localhost address from the new tab and paste it here. This also works when the browser says that the localhost page is unavailable.",
  "cloudflare.callbackUrl": "URL from the localhost address bar",
  "cloudflare.finishConnection": "Finish connection",
  "cloudflare.signInCallback": "Sign in through the panel callback",
  "cloudflare.loadingZones": "Loading zones…",
  "cloudflare.noZones": "No zones are available. Check connection permissions.",
  "cloudflare.loadingRecords": "Loading DNS records…",
  "cloudflare.noRecords": "There are no DNS records yet.",
  "cloudflare.readOnlyRecord": "This record type is read-only.",
  "cloudflare.dnsHint":
    "DNS stores addresses without paths or ports. Cloudflare proxy does not serve arbitrary TCP/UDP ports.",
  "cloudflare.connection": "Connection",
  "cloudflare.type": "Type", "cloudflare.valueHint": "Enter the value manually without a scheme, path, or port.",
  "errors.generic": "Action failed.",
  "errors.connecting": "Connecting to service…",
  "errors.saveRoute": "Failed to save route.",
  "errors.requiredField": "Fill in “{name}”.",
  "errors.nonNegativeNumber": "Enter a non-negative number in “{name}”.",
  "errors.invalidPort": "Enter a port from 1 to 65535.",
  "oauth.signIn": "Sign in with Cloudflare",
  "oauth.opening": "Opening Cloudflare…",
  "oauth.approved": "Access approved.",
  "oauth.failed": "Cloudflare connection failed. Sign in again from the panel.",
  "oauth.close": "Close window",
  "oauth.openPanel": "Open panel",
  "errors.staleSession": "The session changed. This response is stale.",
  "errors.transport":
    "The server is unavailable or the request timed out. Try again.",
  "errors.incorrectPassword": "Incorrect password. Try again.",
  "errors.sessionEnded": "The session ended. Sign in again.",
  "errors.server": "Server error (HTTP {status})",
  "errors.unknownResponse": "The server returned data in an unknown format.",
  "errors.cloudflareAuthorizationUrl":
    "The server returned an invalid Cloudflare authorization URL.",
  "data.unavailable": "no data",
};

let locale: Locale = "en";
let preference = "en";
const listeners = new Set<() => void>();
export function resolveLanguage(_languages: readonly string[]): Locale { return "en"; }
export function getLocale() { return locale; }
export function getLanguagePreference() { return preference; }
export function setLocale(next: string) {
  if (next !== "en" && next !== "system") return;
  locale = "en";
  preference = next;
  try { localStorage.setItem("niceproxy-language", next); } catch {}
  document.documentElement.lang = "en";
  listeners.forEach((listener) => listener());
}
export function t(key: string, values?: Record<string, string | number>) {
  const value = en[key] ?? key;
  return values ? value.replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? `{${name}}`)) : value;
}
export function useI18n() {
  const [, render] = useState(0);
  useEffect(() => {
    const listener = () => render((value) => value + 1);
    listeners.add(listener);
    document.documentElement.lang = "en";
    return () => { listeners.delete(listener); };
  }, []);
  return { locale, preference, t, locales };
}
