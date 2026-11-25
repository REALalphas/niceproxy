# Cloudflare account connection

niceproxy uses OAuth 2.0 Authorization Code with PKCE (S256). You can connect Cloudflare from the LAN management listener before the public domain can serve HTTPS.

## Register the app once

1. Open **Cloudflare DNS** in niceproxy and choose **Connect Cloudflare** or **OAuth settings**. Copy the displayed Redirect URI. It uses localhost and your management port, for example `http://localhost:9080/api/cloudflare/callback`.
2. Create a Cloudflare OAuth client with private visibility for your account. Paste that URI exactly, choose authorization code and **None** for token authentication, and select the scopes below.
3. Copy the Client ID and scope IDs back into niceproxy and save them.
4. Choose **Sign in with Cloudflare** and open the authorization link in the new tab. After approving access, copy the complete localhost URL from the address bar back into the open niceproxy form and finish the connection. A browser can show a connection error because localhost refers to the machine running the browser. The address bar still contains the URL needed to finish the flow.

Open [Cloudflare → Manage Account → OAuth clients](https://dash.cloudflare.com/?to=/:account/oauth-clients), create a client, and fill the form as follows:

| Cloudflare field | Value |
| --- | --- |
| **Client Name** | `niceproxy` or another name for this installation |
| **Response Type** | `Code` |
| **Grant type** | `Authorization Code` |
| **Token Authentication Method** | `None` |
| **Redirect (Callback) URLs** | The localhost URI displayed in niceproxy. Add the public HTTPS callback too if you want to sign in directly from that hostname. |
| **Client URL** *(optional)* | Leave empty |
| **Logo** *(optional)* | Leave empty |
| **Policy URL** *(optional)* | Leave empty |
| **Terms of Service URL** *(optional)* | Leave empty |
| **Post-logout Redirect URLs** *(optional)* | Leave empty |
| **Allowed CORS Origins** *(optional)* | Leave empty |

niceproxy uses Authorization Code with PKCE S256, so a client secret is not needed. Add `offline_access` to the granted scopes when refresh access is required.

### Public callback URL

The localhost flow works whether or not a public panel hostname is configured. After provisioning HTTPS, you can optionally also register the public callback, for example `https://panel.example.com/api/cloudflare/callback`. Open the panel on that hostname to use its direct callback. A domain change updates the advertised public callback. Update the registered public URI before using it for a new sign-in. The existing OAuth grant and localhost setup survive panel hostname changes.

### Public domain and Caddy HTTPS

`NICEPROXY_DOMAIN` is optional. When set, it is both the panel hostname and the Cloudflare callback hostname. Caddy creates the HTTPS route to the management panel and redirects HTTP to HTTPS. DNS Only uses a publicly trusted ACME certificate. Proxied mode can use Cloudflare Origin CA.

Create an A/AAAA record for the hostname pointing to the niceproxy origin. Forward external TCP 80 and 443 to the ports in `NICEPROXY_HTTP_PORT` and `NICEPROXY_HTTPS_PORT`. The domain must be reachable from the public Internet while Caddy completes ACME validation. Do not create a separate user HTTP route for this hostname because it is reserved for the panel.

The internal HTTPS port is not part of the public URL. With `NICEPROXY_HTTPS_PORT=18443` and router forwarding public 443 to 18443, the browser URL remains `https://cf.example.com`, without `:18443`.

To test the NAS listener directly, connect to the LAN IP and internal port while keeping the panel hostname for SNI and HTTP. Replace the example IP with the NAS LAN address. Use a copy of the origin's root CA certificate when Caddy serves its local bootstrap certificate.

```sh
curl --connect-to panel.example.com:443:192.0.2.10:18443 \
  --cacert ./origin-root.crt https://panel.example.com/
```

This probe checks the origin route and the presented certificate. The system resolver diagnostics in **Service** include hosts-file overrides. Public DNS and the router forwarding used by the ACME CA require a separate check. When switching from Proxied to DNS Only, niceproxy returns to Caddy's public ACME policy. A Cloudflare Origin CA certificate stays on disk for subsequent use in Proxied mode.

The configured callback also appears as a separate card in **Routes**. This card identifies the reserved panel and OAuth hostname. It is not a user-created proxy rule.

### Automatic panel TLS

Connect Cloudflare through the localhost OAuth flow with the zone permissions below. Niceproxy uses this OAuth connection to detect DNS and encryption modes, provision an origin certificate and manage the panel's Full (strict) rule.

| Cloudflare mode | What niceproxy does |
| --- | --- |
| DNS Only | Uses public ACME with HTTP-01 / TLS-ALPN-01. Keep the challenge ports publicly reachable. |
| Proxied with Flexible, Full, or Off | Verifies the origin certificate or issues a dedicated Origin CA certificate. Then sets Full (strict) with a Configuration Rule scoped to the panel hostname. |
| Proxied with Automatic SSL/TLS | Uses the zone's current encryption mode and the same hostname-specific logic. Automatic stays enabled for the zone. |
| Proxied with Full (strict) | Keeps the mode when Configuration Rules already preserve strict TLS for the panel. If a rule can weaken TLS for the panel, adds a hostname-specific strict rule. |

niceproxy checks on startup, after applying panel settings, and once a minute. It preserves the DNS record and zone-wide SSL settings. It renews its Origin CA certificate before expiry. A public website behind Cloudflare still needs an active edge certificate and public TCP 443 forwarded to Caddy's HTTPS listener. While Flexible forwards a viewer's HTTPS request to origin HTTP, Caddy returns a diagnostic 503 so the panel never handles credentials over that connection.

**Service** shows the last DNS mode read from Cloudflare, the zone's encryption mode, local SNI verification and any issue preventing the next step. A successful local verification checks Caddy's listener. To confirm public access and the OAuth callback, test HTTPS from outside the LAN. For a CNAME, ensure its target resolves directly when testing DNS Only. Cloudflare can proxy traffic when a target in the CNAME chain is proxied.

The managed HTTPS route follows the configured panel hostname. The OAuth connection established on the LAN lets niceproxy provision the certificate before the public hostname is usable.

### Use an Origin CA certificate with Proxied

Cloudflare uses its edge certificate for the visitor connection. To use Full (strict), give Caddy an Origin CA certificate for the panel hostname. Under **SSL/TLS → Origin Server**, issue a dedicated certificate for that one hostname. Remove additional DNS names, wildcard names, and IP addresses from the request so the certificate stays scoped to the panel route.

Place the PEM certificate and private key in the persistent data directory or a separate bind mount. Allow the niceproxy UID to read them and keep the private key at mode `0600`. Provide the container paths as environment variables and redeploy. For example:

```yaml
NICEPROXY_PANEL_CERT_FILE: /data/tls/panel.crt
NICEPROXY_PANEL_KEY_FILE: /data/tls/panel.key
```

niceproxy checks the hostname, validity dates, and matching private key before loading the pair. If the pair is unusable, Caddy uses its managed panel policy and the certificate status reports the problem. In **Service**, verify that local origin TLS reports Cloudflare Origin CA. With API access, niceproxy checks the SSL mode and configures Full (strict) when needed. For a manual setup, enable Full (strict) in Cloudflare. Restart niceproxy after replacing the files so Caddy reloads them.

Origin CA issuance requires **SSL and Certificates Edit**. Importing a certificate pair works independently of OAuth. [Cloudflare Origin CA documentation](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)

### Scope IDs and saving settings

1. Select **Zone Read** and **DNS Read** for discovery and **DNS Write** for editing records. For automatic panel TLS, also select **Zone Settings Read**, **SSL and Certificates Edit**, and **Config Settings Read/Write**. Include `offline_access` for refresh access. Grant access to the panel's zone.
2. Cloudflare ties these permissions to OAuth scope IDs. Enter the IDs shown for the registered client in niceproxy's **Scope ID** field, separated by spaces or commas. Do not use API token permission names or invented `dns:*` values. Cloudflare also exposes valid IDs at `/client/v4/oauth/scopes`.
3. Save the public Client ID and scope IDs in the niceproxy Cloudflare panel. These are app settings, not account secrets.
4. Click **Sign in with Cloudflare** and approve the requested access.

## Cloudflare dashboard checklist

The panel reports detected proxy mode and automation state at `/api/panel-domain` and exposes the certificate and SNI state at `/api/certificate`. A `waiting_acme` health state with equal desired and applied revisions means Caddy has loaded the panel route and is waiting for a trusted certificate. Without API access, verify the record's actual Cloudflare proxy status in the dashboard.

### DNS → Records

- [ ] **Type**: `A` for an IPv4 origin or `AAAA` for an IPv6 origin.
- [ ] **Name**: the callback subdomain, for example `cf`.
- [ ] **Content**: the public IP address of the router or host that forwards traffic to niceproxy.
- [ ] **Proxy status**: `Proxied` when Cloudflare should sit in front of the panel, or `DNS only` while testing direct origin access.
- [ ] **TTL**: `Auto`.

The resulting hostname must match `NICEPROXY_DOMAIN`, such as `cf.example.com`. Do not put `http://`, a port, or `/api/cloudflare/callback` into the DNS record.

### SSL/TLS → Overview

- [ ] **Encryption mode for the panel hostname**: `Full (strict)` when Proxied. Verify the hostname-specific rule or use the zone setting for a manual setup.

### SSL/TLS → Edge Certificates

- [ ] **Always Use HTTPS**: `On` when the hostname is proxied through Cloudflare.
- [ ] **Automatic HTTPS Rewrites**: `On`.

These settings affect the browser-to-Cloudflare connection. Caddy still terminates HTTPS on the origin.

### Cloudflare → OAuth clients

- [ ] **Client Name**: `niceproxy`.
- [ ] **Response Type**: `Code`.
- [ ] **Grant type**: `Authorization Code`.
- [ ] **Token Authentication Method**: `None`.
- [ ] **Redirect (Callback) URLs**: copy the localhost URI shown in the panel. Optionally also register the public HTTPS URI.
- [ ] **Client URL**, **Logo**, **Policy URL**, **Terms of Service URL**, **Post-logout Redirect URLs**, and **Allowed CORS Origins**: leave empty.

### Fully local mode without SSL

- [ ] Leave `NICEPROXY_DOMAIN` empty.
- [ ] Keep the panel on `127.0.0.1`.
- [ ] Use the displayed localhost callback, for example `http://localhost:9080/api/cloudflare/callback`.
- [ ] Paste that callback into Cloudflare OAuth **Redirect (Callback) URLs**.
- [ ] Do not use Cloudflare proxy or Cloudflare SSL settings for this local-only callback.

The local mode is HTTP by design. A public callback domain uses HTTPS through Caddy and should use Cloudflare `Full (strict)`.

### Error meanings

- **Cloudflare 521** means the origin is not accepting the connection. Check the router forwarding to `NICEPROXY_HTTP_PORT` and `NICEPROXY_HTTPS_PORT`, the host firewall, and Caddy logs.
- **Cloudflare 525** means Cloudflare reached the origin but the TLS handshake failed. Check that Caddy is listening on the forwarded HTTPS port, that `NICEPROXY_DOMAIN` matches the requested hostname, and that Caddy has obtained a certificate.
- A missing certificate on a DNS-only record requires public TCP 80 and 443 reachability for ACME. For a proxied record, use a certificate Cloudflare trusts. Built-in HTTP-01 and TLS-ALPN-01 work directly against the origin in DNS-only mode. The panel's system-managed route shows the prerequisite. While Proxied, Caddy uses a local bootstrap certificate until a trusted origin certificate is available.

A private client is available to members of its account. A shared client for other accounts requires public visibility and publisher domain verification. Personal installations can remain private.

See [OAuth client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), and [access management](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

After sign-in, the panel lists zones and records allowed by the grant. It can explicitly create A, AAAA, or CNAME records and edit selected records. Existing records are never overwritten automatically. Connecting an account or creating a niceproxy route does not change DNS by itself.

DNS points to a server address, without a port or path. Cloudflare proxy defaults to DNS only and does not publish arbitrary TCP/UDP ports. This integration does not create a Cloudflare Tunnel or change niceproxy traffic flow. Caddy still issues HTTP/HTTPS certificates. Cloudflare DNS-01 is not integrated in this version.

## Client IP for the panel

The public HTTPS panel automatically uses `CF-Connecting-IP` for login rate limiting when the connecting peer matches one of the official Cloudflare IPv4 or IPv6 ranges bundled with niceproxy. Direct and local access, a missing or invalid header, and connections where SNAT or a load balancer hides the Cloudflare peer all fall back to the visible peer address.

The bundled list works offline. If the published ranges change before the next niceproxy upgrade, set `NICEPROXY_PANEL_CLOUDFLARE_CIDRS` to the full replacement list, separated by commas or whitespace, and restart niceproxy. [Cloudflare's published ranges](https://www.cloudflare.com/ips/)

## Data and access

Access and refresh tokens are encrypted in SQLite with AES-GCM. `/data/cloudflare.key` uses mode `0600`. Native runs store it under `--data`. Back up the database and key together. A lost key cannot be replaced while the saved connection remains. Tokens are never returned by the panel API or written to logs.

OAuth start requires an administrator session. For the localhost flow, completion requires the same authenticated session, the exact loopback URI, one-time state, and PKCE. For the direct callback, the browser's temporary state cookie binds the return request to the initiating session. Disconnect removes the local connection and attempts Cloudflare revocation. If the network call fails, the panel links to manual revocation.

`NICEPROXY_DOMAIN` sets the panel and public callback hostname. Changing the OAuth Client ID or scopes requires a new grant.

A real sign-in needs a registered client and valid scopes. Without them, the panel shows setup state. Local OAuth/API test servers cover the protocol, refresh, and DNS client. The real account is connected by the user.
