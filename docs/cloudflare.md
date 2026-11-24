# Cloudflare account connection

niceproxy uses OAuth 2.0 Authorization Code + PKCE (S256). **Sign in with Cloudflare** opens Cloudflare in a separate window. Choose an account and approve access. The window closes and the panel loads available zones. If popups are blocked, sign-in continues in the current tab. A registered public OAuth client is required.

## Register the app once

Cloudflare requires a registered OAuth client. Register niceproxy in your own Cloudflare account.

Choose one deployment mode before configuring Cloudflare.

### 1. Public domain with SSL

```dotenv
NICEPROXY_DOMAIN=cf.toxl.fun
NICEPROXY_PANEL_LISTEN=10.0.3.1:19080
NICEPROXY_HTTP_PORT=18080
NICEPROXY_HTTPS_PORT=18443
```

Create DNS for `cf.toxl.fun`, forward public TCP 80 to `18080` and public TCP 443 to `18443`, then restart the container. Caddy requests the certificate and serves the panel at `https://cf.toxl.fun`.

### 2. Fully local without SSL

```dotenv
NICEPROXY_DOMAIN=
NICEPROXY_PANEL_LISTEN=127.0.0.1:9080
```

Use the local HTTP callback shown in the panel. Do not put a public domain behind Cloudflare in this mode.

Open [Cloudflare → Manage Account → OAuth clients](https://dash.cloudflare.com/?to=/:account/oauth-clients), create a client, and fill the form as follows:

| Cloudflare field | Value |
| --- | --- |
| **Client Name** | `niceproxy` or another name for this installation |
| **Response Type** | `Code` |
| **Grant type** | `Authorization Code` |
| **Token Authentication Method** | `None` |
| **Redirect (Callback) URLs** | The exact callback shown in the niceproxy panel, one URL |
| **Client URL** *(optional)* | Leave empty |
| **Logo** *(optional)* | Leave empty |
| **Policy URL** *(optional)* | Leave empty |
| **Terms of Service URL** *(optional)* | Leave empty |
| **Post-logout Redirect URLs** *(optional)* | Leave empty |
| **Allowed CORS Origins** *(optional)* | Leave empty |

niceproxy uses Authorization Code with PKCE S256, so a client secret is not needed. Add `offline_access` to the granted scopes when refresh access is required.

### Callback URL

For a fully local installation, the panel derives this callback automatically:

```text
http://127.0.0.1:9080/api/cloudflare/callback
```

Copy the value with the **Copy** button in the niceproxy panel and paste it into Cloudflare's **Redirect (Callback) URLs** field. A domain is not required for a loopback callback.

For a public callback domain, set `NICEPROXY_DOMAIN` and restart niceproxy. Caddy will serve the domain, obtain its HTTPS certificate, and proxy the panel and callback path. For Docker, add this to `.env`:

```dotenv
NICEPROXY_DOMAIN=cf.example.com
```

The resulting callback is `https://cf.example.com/api/cloudflare/callback`. Do not register `0.0.0.0`, a container address, or a URL with query parameters. For another local port, replace `9080`, for example `http://127.0.0.1:19080/api/cloudflare/callback`.

### Public domain and Caddy HTTPS

`NICEPROXY_DOMAIN` is optional. When set, it is both the panel hostname and the Cloudflare callback hostname. Caddy creates the HTTPS route to the management panel and requests a public ACME certificate. It also redirects HTTP to HTTPS.

Create an A/AAAA record for the hostname pointing to the niceproxy origin. Forward external TCP 80 and 443 to the ports in `NICEPROXY_HTTP_PORT` and `NICEPROXY_HTTPS_PORT`. The domain must be reachable from the public Internet while Caddy completes ACME validation. Do not create a separate user HTTP route for this hostname because it is reserved for the panel.

The internal HTTPS port is not part of the public URL. With `NICEPROXY_HTTPS_PORT=18443` and router forwarding public 443 to 18443, the browser URL remains `https://cf.example.com`, without `:18443`.

The configured callback also appears as a separate card in **Routes**. This card identifies the reserved panel and OAuth hostname. It is not a user-created proxy rule.

### Scope IDs and saving settings

1. Grant only Zone Read, DNS Read, DNS Write, and `offline_access` for the required resources.
2. Cloudflare ties these permissions to OAuth scope IDs. Enter the IDs shown for the registered client in niceproxy's **Scope ID** field, separated by spaces or commas. Do not use API token permission names or invented `dns:*` values. Cloudflare also exposes valid IDs at `/client/v4/oauth/scopes`.
3. Save the public Client ID and scope IDs in the niceproxy Cloudflare panel. These are app settings, not account secrets.
4. Click **Sign in with Cloudflare** and approve the requested access.

## Cloudflare dashboard checklist

### DNS → Records

- [ ] **Type**: `A` for an IPv4 origin or `AAAA` for an IPv6 origin.
- [ ] **Name**: the callback subdomain, for example `cf`.
- [ ] **Content**: the public IP address of the router or host that forwards traffic to niceproxy.
- [ ] **Proxy status**: `Proxied` when Cloudflare should sit in front of the panel, or `DNS only` while testing direct origin access.
- [ ] **TTL**: `Auto`.

The resulting hostname must match `NICEPROXY_DOMAIN`, such as `cf.toxl.fun`. Do not put `http://`, a port, or `/api/cloudflare/callback` into the DNS record.

### SSL/TLS → Overview

- [ ] **Encryption mode**: `Full (strict)`.

This is the SSL mode for `NICEPROXY_DOMAIN`. Caddy obtains a valid public certificate for the origin, so Cloudflare can verify it. `Flexible` is not suitable because it sends HTTP to an origin that redirects to HTTPS. `Full` is weaker than `Full (strict)` and is useful only while diagnosing a certificate problem.

### SSL/TLS → Edge Certificates

- [ ] **Always Use HTTPS**: `On` when the hostname is proxied through Cloudflare.
- [ ] **Automatic HTTPS Rewrites**: `On`.

These settings affect the browser-to-Cloudflare connection. Caddy still terminates HTTPS on the origin.

### Cloudflare → OAuth clients

- [ ] **Client Name**: `niceproxy`.
- [ ] **Response Type**: `Code`.
- [ ] **Grant type**: `Authorization Code`.
- [ ] **Token Authentication Method**: `None`.
- [ ] **Redirect (Callback) URLs**: copy `https://<NICEPROXY_DOMAIN>/api/cloudflare/callback` from the panel.
- [ ] **Client URL**, **Logo**, **Policy URL**, **Terms of Service URL**, **Post-logout Redirect URLs**, and **Allowed CORS Origins**: leave empty.

### Fully local mode without SSL

- [ ] Leave `NICEPROXY_DOMAIN` empty.
- [ ] Keep the panel on `127.0.0.1`.
- [ ] Use the local callback `http://127.0.0.1:9080/api/cloudflare/callback`.
- [ ] Paste that callback into Cloudflare OAuth **Redirect (Callback) URLs**.
- [ ] Do not use Cloudflare proxy or Cloudflare SSL settings for this local-only callback.

The local mode is HTTP by design. A public callback domain uses HTTPS through Caddy and should use Cloudflare `Full (strict)`.

### Error meanings

- **Cloudflare 521** means the origin is not accepting the connection. Check the router forwarding to `NICEPROXY_HTTP_PORT` and `NICEPROXY_HTTPS_PORT`, the host firewall, and Caddy logs.
- **Cloudflare 525** means Cloudflare reached the origin but the TLS handshake failed. Check that Caddy is listening on the forwarded HTTPS port, that `NICEPROXY_DOMAIN` matches the requested hostname, and that Caddy has obtained a certificate.

A private client is available to members of its account. A shared client for other accounts requires public visibility and publisher domain verification. Personal installations can remain private.

See [OAuth client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), and [access management](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

After sign-in, the panel lists zones and records allowed by the grant. It can explicitly create A, AAAA, or CNAME records and edit selected records. Existing records are never overwritten automatically. Connecting an account or creating a niceproxy route does not change DNS by itself.

DNS points to a server address, without a port or path. Cloudflare proxy defaults to DNS only and does not publish arbitrary TCP/UDP ports. This integration does not create a Cloudflare Tunnel or change niceproxy traffic flow. Caddy still issues HTTP/HTTPS certificates. Cloudflare DNS-01 is not integrated in this version.

## Data and access

Access and refresh tokens are encrypted in SQLite with AES-GCM. `/data/cloudflare.key` uses mode `0600`. Native runs store it under `--data`. Back up the database and key together. A lost key cannot be replaced while the saved connection remains. Tokens are never returned by the panel API or written to logs.

OAuth start requires an administrator session. The callback validates one-time state, PKCE, and the initiating session. Disconnect removes the local connection and attempts Cloudflare revocation. If the network call fails, the panel links to manual revocation.

`NICEPROXY_DOMAIN` sets the panel and callback hostname. Loopback panels derive a local HTTP callback automatically when the variable is empty. Changing the domain or OAuth settings disconnects the old grant.

A real sign-in needs a registered client and valid scopes. Without them, the panel shows setup state. Local OAuth/API test servers cover the protocol, refresh, and DNS client. The real account is connected by the user.
