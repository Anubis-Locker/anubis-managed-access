# 🔗 Anubis managed access

Shared managed-instance client and reverse Web gateway for Anubis-Security-Tool.
The client initiates outbound TLS connections; no public listener or firewall
opening is required on the managed PC. HTTP bodies and WebSocket streams travel
over authenticated per-request binary channels, including file transfers.

[Website](https://anubis.locker) · [Desktop](https://github.com/Anubis-Locker/anubis) · [Web](https://github.com/Anubis-Locker/anubis-web)

Enrollment, administrator approval, browser access and profile authentication are
separate boundaries. This transport does not reset Windows or application
passwords and does not turn SYSTEM/session 0 into an interactive desktop.

`createAgent` is exported from the package root; `createGateway` is exported from
`@ai-security-tool/managed-access/server`. Node 20 or newer is required.

An installation persists a random UUID and 256-bit credential in its private
profile. The controller stores only its SHA-256 fingerprint. First enrollment is
**pending**, not trusted: an administrator must verify the fingerprint shown by the
local application and approve it. Reconnection preserves this decision. Revocation
closes active transport channels and invalidates browser sessions.

## Moving a user installation to a SYSTEM service

Managed identity is **profile-specific, not machine-specific**. Its fingerprint
is SHA-256 of the UTF-8 hex credential, not a hardware fingerprint. A different
private `identityFile` on the same PC creates an independent random UUID and
credential. No key-rotation or credential-replacement endpoint is needed.

1. Keep the original user profile and identity file intact. Give the service a
   fresh, persistent SYSTEM-owned profile and `identityFile`; restrict its Windows
   ACL to SYSTEM and the authorized administrators. The file's `mode: 0o600`
   creation option does not configure Windows ACLs. Do not copy the user identity,
   reuse its UUID, or expose the new credential in logs or operator reports.
2. Start the service with that fresh identity file. The client POSTs
   `/api/agents/enroll` with `{ id, secret, label, app, version, platform, arch }`.
   `id` is a lowercase UUID v4 and `secret` is 64 lowercase hex characters;
   metadata fields are optional strings, truncated to 128 characters. A new ID
   returns HTTP 201 with `{ id, status: "pending", fingerprint }`. This request
   does not need administrator authentication, but pending credentials cannot
   open tunnels or obtain access grants.
3. Independently verify the new ID and fingerprint reported by the SYSTEM
   service. An authenticated administrator lists records using
   `GET /api/agents` (response `{ agents: [...] }`) and explicitly approves the
   **new** ID using `POST /api/agents/:id/approve` with no body. Success returns
   HTTP 200 and the public agent record. The gateway delegates administrator
   authentication to its `isAdmin(req)` callback; the managed credential itself
   grants no administrator authority. Approval does not verify a fingerprint
   supplied in the request, so the administrator must verify before approving.
4. Wait for the new record to be approved and `online: true`, with the service's
   local readiness probe passing. Its device hostname changes with its new UUID.
   Obtain fresh browser tickets or MCP grants for this new record; grants from
   the legacy installation are not transferable.
5. Legacy approval, sessions and active channels remain unchanged. If retiring
   that access is separately authorized, an administrator can POST
   `/api/agents/:oldId/revoke`; revocation closes its active channels and
   invalidates browser/MCP grants and unused tickets. Do not revoke the original
   record merely to test migration or before verifying service availability.

Repeated enrollment with the same ID and secret returns HTTP 200 and preserves
`pending`, `approved` or `revoked` status; it may refresh the supplied metadata.
Using an existing ID with a different secret returns HTTP 409 without replacing
that record. Fingerprints are not deduplicated across different IDs: manually
reusing a secret under a new UUID would still enroll, so a genuinely fresh
service profile must generate **both** values. Approval and scopes are never
inherited from another record. Reuse the service's own identity file on restart;
do not regenerate it each time.

Operators authenticate separately to the controller. An approved, healthy agent
can issue a short-lived, one-use browser ticket, exchanged by HTTPS POST for a
host-only, HttpOnly, Secure, SameSite session cookie. Device hostnames are isolated
as `device-<installation-UUID-without-hyphens>.anubis.locker`; wildcard DNS and TLS
must be configured. Tickets and administrator credentials are not placed in URLs.
The gateway strips its cookie and reserved headers before forwarding to the local
application. Existing standalone Web user authentication remains in force.

For external MCP clients, an administrator can POST
`/api/agents/:id/mcp-token` for an approved, online device. The response contains
`url`, `token`, `scope: "mcp"` and `expiresAt`. Supply the token as
`Authorization: Bearer <token>` to the returned HTTPS `/mcp` endpoint. It expires
after at most one hour and permits only GET, POST and DELETE on that device's exact
`/mcp` path, including query parameters. It cannot open the browser UI, controller
APIs or WebSockets. The gateway removes this credential before forwarding;
the application's private transport-authenticated adapter handles local MCP
authentication without uploading its local key. The local authenticated MCP
widget must actually be running. Expiration closes active HTTP/SSE streams;
revocation invalidates all browser and MCP grants and closes active channels.
MCP response headers may take up to 130 seconds, accommodating the existing
120-second synchronous command timeout; ordinary Web responses retain 30 seconds.

## Windows contexts in a managed browser

A compatible Windows machine host can offer SYSTEM and policy-authorized
interactive Windows sessions. This is not an application administrator/user role
toggle, and standalone Web on Linux does not acquire Windows identities.
The device page loads `/_anubis/context-ui.js` only when the host supports this
contract. Its chooser displays the real Windows account, SID and session.

`GET /_anubis/contexts` requires the authenticated device browser cookie and
returns sanitized choices plus the current identity. `POST` to the same path
requires same-origin JSON containing only a listed opaque `id`. The gateway
requests the change through the SYSTEM transport, rotates its browser cookie
without extending its lifetime, and closes only that browser session's existing
HTTP/WebSocket channels. Other browsers remain in their own contexts. The
browser clears its old `tokenElecterm` and reloads; the selected Windows profile
still requires its own application password and retains its own DPAPI data.
An expired logon or failed selection never selects a fallback account.

The gateway strips browser-supplied `x-anubis-managed-session` and
`x-anubis-managed-context` headers. It supplies a random server-only session
binding and the host-issued selector on HTTP and WebSocket requests. The native
adapter revalidates Windows policy/logon identity, and loopback ports, transport
proofs and local tokens never reach the browser. The internal
`/api/machine-contexts` route cannot be called directly through the public
gateway. MCP-only grants cannot list or change contexts and remain SYSTEM scoped.
Cookie rotation preserves the server-only binding; the old cookie is revoked.

`createAgent` takes `baseUrl`, `identityFile`, `localPort`, optional fixed loopback
`localHost`, `label`, `app`, `version`, async `probe`, `onStatus`, and optional
`localHeaders`. The latter are injected into the first HTTP request of each local
connection, replacing incoming matching headers. The local HTTP application must
disable keepalive for these channels; WebSocket upgrades remain full duplex.
`start()` is nonblocking and idempotent. `stop()` closes outbound channels and
retry timers; create a new agent object to start again. Status includes the public
`id`, `fingerprint`, `status`, an `error` when applicable, and `url` only when ready.

The gateway is attached to an existing Node HTTP server through `handle(req,res)`
and `upgrade(req,socket,head)`. `handle` returns whether it handled the request.
`close()` releases all gateway connections. Supply a private `dataDir` and an
`isAdmin(req)` authentication callback.

Run `npm ci` and `npm test` for real enrollment/approval, HTTP binary streaming,
WebSocket echo, readiness, credential collision and revocation checks. Migration
coverage uses synthetic user/service identities on the same loopback gateway,
verifies independent approval and grants, and preserves the legacy profile,
record and live transport. Tests do not alter a production controller.
