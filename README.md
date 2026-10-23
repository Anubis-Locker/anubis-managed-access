# Anubis managed access

Shared managed-instance client and reverse Web gateway for Anubis-Security-Tool.
The client initiates outbound TLS connections; no public listener or firewall
opening is required on the managed PC. HTTP bodies and WebSocket streams travel
over authenticated per-request binary channels, including file transfers.

`createAgent` is exported from the package root; `createGateway` is exported from
`@ai-security-tool/managed-access/server`. Node 20 or newer is required.

An installation persists a random UUID and 256-bit credential in its private
profile. The controller stores only its SHA-256 fingerprint. First enrollment is
**pending**, not trusted: an administrator must verify the fingerprint shown by the
local application and approve it. Reconnection preserves this decision. Revocation
closes active transport channels and invalidates browser sessions.

Operators authenticate separately to the controller. An approved, healthy agent
can issue a short-lived, one-use browser ticket, exchanged by HTTPS POST for a
host-only, HttpOnly, Secure, SameSite session cookie. Device hostnames are isolated
as `device-<installation-UUID-without-hyphens>.anubis.locker`; wildcard DNS and TLS
must be configured. Tickets and administrator credentials are not placed in URLs.
The gateway strips its cookie and reserved headers before forwarding to the local
application. Existing standalone Web user authentication remains in force.

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
WebSocket echo, readiness, credential collision and revocation checks. They use
loopback fixtures and do not alter a production controller.
