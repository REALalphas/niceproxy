# Cloudflare account connection

niceproxy uses OAuth 2.0 Authorization Code + PKCE (S256). **Sign in with Cloudflare** opens Cloudflare in a separate window. Choose an account and approve access. The window closes and the panel loads available zones. If popups are blocked, sign-in continues in the current tab. A registered public OAuth client is required.

## Register the app once

Cloudflare requires a registered OAuth client. Register niceproxy in your own Cloudflare account.

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

If the panel listens on a LAN address, `0.0.0.0`, or a domain, set `NICEPROXY_CF_REDIRECT_URL` and restart niceproxy. For Docker, add this to `.env`:

```dotenv
NICEPROXY_CF_REDIRECT_URL=https://panel.example.com/api/cloudflare/callback
```

The Cloudflare value and niceproxy value must match exactly, including scheme, hostname, and port. Remote callbacks require HTTPS. Do not register `0.0.0.0`, a container address, or a URL with query parameters. For another local port, replace `9080`, for example `http://127.0.0.1:19080/api/cloudflare/callback`.

### Callback subdomain

To use a dedicated domain or subdomain, fill **Callback domain for Cloudflare** in niceproxy with a hostname such as `cf.example.com`. niceproxy builds `https://cf.example.com/api/cloudflare/callback`, saves the setting, and shows the resulting URL for copying.

Create the DNS record for that hostname and configure an HTTPS reverse proxy to the niceproxy panel separately. After saving, open niceproxy through that hostname. The OAuth start and callback checks require the request Host to match the configured hostname.

The configured callback also appears as a separate card in **Routes**. This card documents the OAuth endpoint and does not add a Caddy route.

### Scope IDs and saving settings

1. Grant only Zone Read, DNS Read, DNS Write, and `offline_access` for the required resources.
2. Cloudflare ties these permissions to OAuth scope IDs. Enter the IDs shown for the registered client in niceproxy's **Scope ID** field, separated by spaces or commas. Do not use API token permission names or invented `dns:*` values. Cloudflare also exposes valid IDs at `/client/v4/oauth/scopes`.
3. Save the public Client ID and scope IDs in the niceproxy Cloudflare panel. These are app settings, not account secrets.
4. Click **Sign in with Cloudflare** and approve the requested access.

A private client is available to members of its account. A shared client for other accounts requires public visibility and publisher domain verification. Personal installations can remain private.

See [OAuth client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), and [access management](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

After sign-in, the panel lists zones and records allowed by the grant. It can explicitly create A, AAAA, or CNAME records and edit selected records. Existing records are never overwritten automatically. Connecting an account or creating a niceproxy route does not change DNS by itself.

DNS points to a server address, without a port or path. Cloudflare proxy defaults to DNS only and does not publish arbitrary TCP/UDP ports. This integration does not create a Cloudflare Tunnel or change niceproxy traffic flow. Caddy still issues HTTP/HTTPS certificates. Cloudflare DNS-01 is not integrated in this version.

## Data and access

Access and refresh tokens are encrypted in SQLite with AES-GCM. `/data/cloudflare.key` uses mode `0600`. Native runs store it under `--data`. Back up the database and key together. A lost key cannot be replaced while the saved connection remains. Tokens are never returned by the panel API or written to logs.

OAuth start requires an administrator session. The callback validates one-time state, PKCE, and the initiating session. Disconnect removes the local connection and attempts Cloudflare revocation. If the network call fails, the panel links to manual revocation.

`NICEPROXY_CF_REDIRECT_URL` sets the default callback URL. Loopback panels derive it automatically. A callback domain saved in the OAuth panel takes precedence and is stored in SQLite with the Client ID and scopes. Changing these settings disconnects the old grant.

A real sign-in needs a registered client and valid scopes. Without them, the panel shows setup state. Local OAuth/API test servers cover the protocol, refresh, and DNS client. The real account is connected by the user.
