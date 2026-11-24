import { request } from "./api";

export type CloudflareStatus = {
  configured: boolean;
  connected: boolean;
  clientId: string;
  redirectUrl: string;
  scopes: string[];
  expiresAt?: string;
  error?: string;
};
export type CertificateStatus = {
  configured: boolean;
  domain: string;
  state: "not_configured" | "pending" | "issued" | "expired" | "error" | "unknown";
  expiresAt?: string;
  error?: string;
};
export type Zone = { id: string; name: string; status: string; account: { id: string; name: string } };
export type DNSRecord = { id: string; type: string; name: string; content: string; proxied: boolean; ttl: number };
export type RecordInput = { name: string; type: "A" | "AAAA" | "CNAME"; content: string; proxied: boolean; ttl: number };
const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === "string");
const status = (v: unknown): v is CloudflareStatus => object(v) &&
  typeof v.configured === "boolean" && typeof v.connected === "boolean" &&
  typeof v.clientId === "string" && typeof v.redirectUrl === "string" && strings(v.scopes) &&
  (v.expiresAt === undefined || typeof v.expiresAt === "string") &&
  (v.error === undefined || typeof v.error === "string");
const certificateStatus = (v: unknown): v is CertificateStatus => object(v) &&
  typeof v.configured === "boolean" && typeof v.domain === "string" &&
  ["not_configured", "pending", "issued", "expired", "error", "unknown"].includes(String(v.state)) &&
  (v.expiresAt === undefined || typeof v.expiresAt === "string") &&
  (v.error === undefined || typeof v.error === "string");
const zone = (v: unknown): v is Zone => object(v) && typeof v.id === "string" &&
  typeof v.name === "string" && typeof v.status === "string" && object(v.account) &&
  typeof v.account.id === "string" && typeof v.account.name === "string";
const dnsRecord = (v: unknown): v is DNSRecord => object(v) && typeof v.id === "string" &&
  typeof v.type === "string" && typeof v.name === "string" && typeof v.content === "string" &&
  typeof v.proxied === "boolean" && Number.isInteger(v.ttl);
export const parseScopes = (value: string): string[] => [...new Set(value.split(/[\s,]+/).filter(Boolean))];
export const supportedRecord = (type: string): type is RecordInput["type"] => ["A", "AAAA", "CNAME"].includes(type);
export function authorizationURL(value: string): string {
  const url = new URL(value);
  if (url.origin !== "https://dash.cloudflare.com" || url.username || url.password)
    throw new Error("The server returned an invalid Cloudflare authorization URL.");
  return url.href;
}
const recordsPath = (id: string) => `/cloudflare/zones/${encodeURIComponent(id)}/records`;
export const cloudflareApi = {
  status: () => request("/cloudflare", status),
  certificate: () => request("/certificate", certificateStatus),
  settings: (clientId: string, scopes: string[]) => request("/cloudflare/settings", status, "POST", { clientId, scopes }),
  connect: () => request("/cloudflare/connect", (v): v is { url: string } => object(v) && typeof v.url === "string", "POST"),
  disconnect: () => request("/cloudflare/disconnect", (v): v is { ok: true; warning?: string } => object(v) && v.ok === true &&
    (v.warning === undefined || typeof v.warning === "string"), "POST"),
  zones: () => request("/cloudflare/zones", (v): v is { zones: Zone[] } => object(v) && Array.isArray(v.zones) && v.zones.every(zone)),
  records: (id: string) => request(recordsPath(id), (v): v is { records: DNSRecord[] } => object(v) && Array.isArray(v.records) && v.records.every(dnsRecord)),
  saveRecord: (zoneId: string, data: RecordInput, id?: string) => request(
    recordsPath(zoneId) + (id ? `/${encodeURIComponent(id)}` : ""), dnsRecord, id ? "PATCH" : "POST", data),
};
