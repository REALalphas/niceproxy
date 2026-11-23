# Cloudflare account connection

niceproxy uses OAuth 2.0 Authorization Code + PKCE (S256). **Sign in with Cloudflare** opens Cloudflare in a separate window. Choose an account and approve access. The window closes and the panel loads available zones. If popups are blocked, sign-in continues in the current tab. A registered public OAuth client is required.

## Register the app once

Cloudflare requires a registered OAuth client. Register niceproxy in your own Cloudflare account.

1. Open [Cloudflare → Manage Account → OAuth clients](https://dash.cloudflare.com/?to=/:account/oauth-clients) and create a niceproxy client.
2. Use response type `code`, grant types `authorization_code` and `refresh_token`, and token endpoint authentication `none` for PKCE.
3. Copy the Redirect URL from the niceproxy Cloudflare panel. Local native default is `http://127.0.0.1:19080/api/cloudflare/callback`; Docker default is `http://127.0.0.1:9080/api/cloudflare/callback`. It must match exactly, including the port. HTTP is allowed only on loopback. Remote callbacks require HTTPS.
4. Grant only Zone Read, DNS Read, DNS Write, and `offline_access` for the required resources. Use the OAuth scope IDs shown for the registered client. Do not use API token permission names or invented `dns:*` values. Cloudflare also exposes valid IDs at `/client/v4/oauth/scopes`.
5. Save the public Client ID and scope IDs in the niceproxy Cloudflare panel. These are app settings, not account secrets.
6. Click **Sign in with Cloudflare** and approve the requested access.

A private client is available to members of its account. A shared client for other accounts requires public visibility and publisher domain verification. Personal installations can remain private.

See [OAuth client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/), [OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/), and [access management](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

## DNS

After sign-in, the panel lists zones and records allowed by the grant. It can explicitly create A, AAAA, or CNAME records and edit selected records. Existing records are never overwritten automatically. Connecting an account or creating a niceproxy route does not change DNS by itself.

DNS points to a server address, without a port or path. Cloudflare proxy defaults to DNS only and does not publish arbitrary TCP/UDP ports. This integration does not create a Cloudflare Tunnel or change niceproxy traffic flow. Caddy still issues HTTP/HTTPS certificates. Cloudflare DNS-01 is not integrated in this version.

## Data and access

Access and refresh tokens are encrypted in SQLite with AES-GCM. `/data/cloudflare.key` uses mode `0600`. Native runs store it under `--data`. Back up the database and key together. A lost key cannot be replaced while the saved connection remains. Tokens are never returned by the panel API or written to logs.

OAuth start requires an administrator session. The callback validates one-time state, PKCE, and the initiating session. Disconnect removes the local connection and attempts Cloudflare revocation. If the network call fails, the panel links to manual revocation.

`NICEPROXY_CF_REDIRECT_URL` sets the registered callback URL. Loopback panels derive it automatically. Client ID and scopes are stored separately from tokens. Changing these settings disconnects the old grant.

A real sign-in needs a registered client and valid scopes. Without them, the panel shows setup state. Local OAuth/API test servers cover the protocol, refresh, and DNS client. The real account is connected by the user.
