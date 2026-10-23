const { test } = require('node:test')
const assert = require('node:assert/strict')
const http = require('node:http')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { WebSocket, WebSocketServer } = require('ws')
const { createAgent, identity } = require('..')
const { createGateway } = require('../server')

async function waitFor (predicate) {
  const until = Date.now() + 10000
  while (!await predicate()) {
    if (Date.now() > until) throw new Error('Managed transport condition timed out')
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

async function fixture (t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anubis-managed-transport-'))
  const upstreamHeaders = []
  const upstream = http.createServer(async (req, res) => {
    upstreamHeaders.push(req.headers)
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    if (req.url === '/mcp?delay=1') await new Promise(resolve => setTimeout(resolve, 31000))
    if (req.url === '/mcp?stream=1') {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.write('data: ready\n\n')
      return
    }
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'x-upstream-path': req.url })
    res.end(chunks.length ? Buffer.concat(chunks) : 'managed real HTTP response')
  })
  const echo = new WebSocketServer({ server: upstream })
  echo.on('connection', (ws, req) => {
    upstreamHeaders.push(req.headers)
    ws.on('message', value => ws.send(value))
    ws.on('error', () => {})
  })
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve))
  const gateway = createGateway({
    dataDir: path.join(dir, 'server'),
    domain: 'anubis.test',
    isAdmin: req => req.headers.authorization === 'Bearer fixture-administrator',
    channelTimeout: 2000,
    ...options
  })
  const server = http.createServer(async (req, res) => {
    if (!await gateway.handle(req, res)) {
      assert.equal(res.headersSent, false, 'Unhandled route already responded: ' + req.url)
      res.writeHead(404)
      res.end()
    }
  })
  server.on('upgrade', gateway.upgrade)
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`
  const states = []
  let ready = true
  const agent = createAgent({
    baseUrl: base,
    identityFile: path.join(dir, 'client.json'),
    localPort: upstream.address().port,
    localHeaders: { 'x-anubis-managed-auth': 'private-local-only' },
    probe: async () => ready,
    onStatus: value => states.push(value),
    heartbeatMs: 50,
    reconnectMs: 50
  })
  t.after(async () => {
    await agent.stop()
    await gateway.close()
    for (const ws of echo.clients) ws.terminate()
    await new Promise(resolve => echo.close(resolve))
    server.closeAllConnections()
    upstream.closeAllConnections()
    await Promise.all([server, upstream].map(value => new Promise(resolve => value.close(resolve))))
    fs.rmSync(dir, { recursive: true, force: true })
  })
  async function api (route, method = 'GET', payload, admin = true) {
    return fetch(base + route, {
      method,
      headers: admin ? { authorization: 'Bearer fixture-administrator' } : {},
      body: payload ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(5000)
    })
  }
  function browser (route, { cookie, method = 'GET', body, headers = {}, timeout = 10000 } = {}) {
    return new Promise((resolve, reject) => {
      const request = http.request(base + route, {
        method,
        headers: {
          host: `device-${agent.id.replace(/-/g, '')}.anubis.test`,
          ...(cookie ? { cookie } : {}),
          ...headers
        }
      }, response => {
        const chunks = []
        response.on('data', chunk => chunks.push(chunk))
        response.on('end', () => resolve({
          status: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks)
        }))
      })
      request.once('error', reject)
      request.setTimeout(timeout, () => request.destroy(new Error('Gateway browser request timed out')))
      request.end(body)
    })
  }
  return { dir, agent, gateway, server, base, states, api, browser, upstreamHeaders, localPort: upstream.address().port, setReady: value => { ready = value } }
}

test('managed identity persists privately and corruption never replaces it', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anubis-managed-id-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'identity.json')
  const first = identity(file)
  assert.deepEqual(identity(file), first)
  assert.match(first.secret, /^[a-f0-9]{64}$/)
  fs.writeFileSync(file, '{invalid')
  assert.throws(() => identity(file))
  assert.equal(fs.readFileSync(file, 'utf8'), '{invalid')
  assert.throws(() => createAgent({ baseUrl: 'http://untrusted.invalid/', identityFile: file, localPort: 1234 }), /HTTPS/)
})

test('fresh service profile enrolls independently without inheriting or changing legacy approval', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  f.agent.start()
  await waitFor(() => f.agent.status === 'pending')
  assert.equal((await f.api(`/api/agents/${f.agent.id}/approve`, 'POST')).status, 200)
  await waitFor(async () => (await (await f.api('/api/agents')).json()).agents[0].online)
  const file = path.join(f.dir, 'server', 'managed-agents.json')
  const legacyRecord = JSON.parse(fs.readFileSync(file, 'utf8'))[f.agent.id]
  const legacyFile = path.join(f.dir, 'client.json')
  const legacyBytes = fs.readFileSync(legacyFile)
  const legacyIdentity = identity(legacyFile)
  const ticket = await (await f.api(`/api/agents/${f.agent.id}/connect`, 'POST')).json()
  const exchanged = await f.browser('/_anubis/connect', {
    method: 'POST', body: JSON.stringify({ ticket: ticket.ticket })
  })
  const cookie = exchanged.headers['set-cookie'][0].split(';')[0]
  const mcp = await (await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST')).json()
  const socket = new WebSocket(f.base.replace('http:', 'ws:') + '/socket', {
    headers: { host: new URL(ticket.url).hostname, cookie }
  })
  t.after(() => socket.terminate())
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject) })

  const serviceFile = path.join(f.dir, 'system-private', 'identity.json')
  const service = createAgent({
    baseUrl: f.base,
    identityFile: serviceFile,
    localPort: f.localPort,
    heartbeatMs: 50,
    reconnectMs: 50
  })
  t.after(() => service.stop())
  const serviceIdentity = identity(serviceFile)
  assert.notEqual(service.id, f.agent.id)
  assert.notEqual(serviceIdentity.secret, legacyIdentity.secret)
  assert.notEqual(service.fingerprint, f.agent.fingerprint)
  assert.equal(service.fingerprint, crypto.createHash('sha256').update(serviceIdentity.secret).digest('hex'))
  assert.deepEqual(identity(serviceFile), serviceIdentity)
  service.start()
  await waitFor(() => service.status === 'pending')
  let listed = (await (await f.api('/api/agents')).json()).agents
  assert.equal(listed.length, 2)
  const pending = listed.find(value => value.id === service.id)
  assert.equal(pending.status, 'pending')
  assert.equal(pending.fingerprint, service.fingerprint)
  assert.equal(pending.platform, legacyRecord.platform)
  assert.equal(pending.arch, legacyRecord.arch)
  assert.equal(pending.online, false)
  assert.equal(pending.url, undefined)
  assert.equal((await f.api(`/api/agents/${service.id}/connect`, 'POST')).status, 503)
  assert.equal((await f.api(`/api/agents/${service.id}/mcp-token`, 'POST')).status, 503)
  for (const secret of [legacyIdentity.secret, serviceIdentity.secret]) {
    const response = await fetch(f.base + `/api/agents/${service.id}/approve`, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + secret },
      signal: AbortSignal.timeout(5000)
    })
    assert.equal(response.status, 401)
  }
  const denied = new WebSocket(f.base.replace('http:', 'ws:') + `/api/agents/${service.id}/tunnel`, {
    headers: { authorization: 'Bearer ' + serviceIdentity.secret }
  })
  const deniedStatus = await new Promise((resolve, reject) => {
    denied.once('open', () => { denied.terminate(); reject(new Error('Pending service opened a tunnel')) })
    denied.once('unexpected-response', (req, res) => {
      const status = res.statusCode
      res.resume()
      denied.terminate()
      resolve(status)
    })
    denied.on('error', () => {})
  })
  assert.equal(deniedStatus, 401)
  for (const [id, secret] of [
    [f.agent.id, serviceIdentity.secret],
    [service.id, legacyIdentity.secret]
  ]) {
    assert.equal((await f.api('/api/agents/enroll', 'POST', { id, secret }, false)).status, 409)
  }
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8'))[service.id].status, 'pending')
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8'))[f.agent.id], legacyRecord)

  const approved = await f.api(`/api/agents/${service.id}/approve`, 'POST')
  assert.equal(approved.status, 200)
  assert.equal((await approved.json()).fingerprint, service.fingerprint)
  await waitFor(async () => {
    listed = (await (await f.api('/api/agents')).json()).agents
    return listed.length === 2 && listed.every(value => value.status === 'approved' && value.online)
  })
  const enrollment = await f.api('/api/agents/enroll', 'POST', serviceIdentity, false)
  assert.equal(enrollment.status, 200)
  assert.equal((await enrollment.json()).status, 'approved')
  const connection = await (await f.api(`/api/agents/${service.id}/connect`, 'POST')).json()
  assert.notEqual(connection.url, ticket.url)
  const serviceHost = { host: new URL(connection.url).hostname }
  assert.equal((await f.browser('/', { cookie, headers: serviceHost })).status, 401)
  assert.equal((await f.browser('/mcp', {
    headers: { ...serviceHost, authorization: 'Bearer ' + mcp.token }
  })).status, 401)
  const serviceExchange = await f.browser('/_anubis/connect', {
    method: 'POST', headers: serviceHost, body: JSON.stringify({ ticket: connection.ticket })
  })
  assert.equal(serviceExchange.status, 200)
  const serviceCookie = serviceExchange.headers['set-cookie'][0].split(';')[0]
  assert.equal((await f.browser('/', { cookie: serviceCookie, headers: serviceHost })).status, 200)
  assert.equal((await f.browser('/', { cookie })).status, 200)
  assert.equal((await f.browser('/mcp', { headers: { authorization: 'Bearer ' + mcp.token } })).status, 200)
  const message = new Promise((resolve, reject) => { socket.once('message', resolve); socket.once('error', reject) })
  socket.send('legacy channel survives independent service approval')
  assert.equal((await message).toString(), 'legacy channel survives independent service approval')
  assert.deepEqual(fs.readFileSync(legacyFile), legacyBytes)
  const persisted = fs.readFileSync(file, 'utf8')
  assert.deepEqual(JSON.parse(persisted)[f.agent.id], legacyRecord)
  assert.equal(JSON.parse(persisted)[service.id].status, 'approved')
  assert.equal(persisted.includes(serviceIdentity.secret), false)
  assert.equal(persisted.includes(legacyIdentity.secret), false)
})

test('real enrolled transport requires approval, streams HTTP and WebSocket, and revokes active access', { timeout: 30000 }, async t => {
  const f = await fixture(t)
  f.agent.start()
  await waitFor(() => f.states.some(value => value.status === 'pending'))
  assert.equal((await f.api('/api/agents', 'GET', undefined, false)).status, 401)
  let listed = await (await f.api('/api/agents')).json()
  assert.equal(listed.agents.length, 1)
  assert.equal(listed.agents[0].online, false)
  assert.equal(listed.agents[0].status, 'pending')
  assert.equal(listed.agents[0].fingerprint, f.agent.fingerprint)
  assert.equal(JSON.stringify(listed).includes(identity(path.join(f.dir, 'client.json')).secret), false)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/connect`, 'POST')).status, 503)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST')).status, 503)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/approve`, 'POST', undefined, false)).status, 401)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST', undefined, false)).status, 401)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/approve`, 'POST')).status, 200)
  await waitFor(() => f.states.some(value => value.status === 'online'))
  await waitFor(async () => (await (await f.api('/api/agents')).json()).agents[0].online)
  assert.equal((await f.browser('/')).status, 401)
  const issued = await (await f.api(`/api/agents/${f.agent.id}/connect`, 'POST')).json()
  assert.equal(new URL(issued.url).hostname, `device-${f.agent.id.replace(/-/g, '')}.anubis.test`)
  const exchanged = await f.browser('/_anubis/connect', { method: 'POST', body: JSON.stringify({ ticket: issued.ticket }) })
  assert.equal(exchanged.status, 200)
  const setCookie = exchanged.headers['set-cookie'][0]
  assert.match(setCookie, /HttpOnly; Secure; SameSite=Strict/)
  const cookie = setCookie.split(';')[0]
  assert.equal((await f.browser('/_anubis/connect', { method: 'POST', body: JSON.stringify({ ticket: issued.ticket }) })).status, 401)
  const response = await f.browser('/real/path?value=1', { cookie, headers: { 'x-anubis-managed-auth': 'spoofed' } })
  assert.equal(response.status, 200)
  assert.equal(response.body.toString(), 'managed real HTTP response')
  assert.equal(response.headers['x-upstream-path'], '/real/path?value=1')
  assert.equal(f.upstreamHeaders.at(-1)['x-anubis-managed-auth'], 'private-local-only')
  assert.equal((f.upstreamHeaders.at(-1).cookie || '').includes('__Host-anubis-gateway'), false)
  const upload = crypto.randomBytes(512 * 1024)
  const echoed = await f.browser('/upload', { cookie, method: 'POST', body: upload })
  assert.equal(echoed.status, 200)
  assert.deepEqual(echoed.body, upload)

  const socket = new WebSocket(f.base.replace('http:', 'ws:') + '/socket', {
    headers: { host: new URL(issued.url).hostname, cookie }
  })
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject) })
  const message = new Promise((resolve, reject) => { socket.once('message', resolve); socket.once('error', reject) })
  socket.send('real browser websocket bytes')
  assert.equal((await message).toString(), 'real browser websocket bytes')
  assert.equal(f.upstreamHeaders.at(-1)['x-anubis-managed-auth'], 'private-local-only')
  f.setReady(false)
  await waitFor(async () => !(await (await f.api('/api/agents')).json()).agents[0].online)
  assert.equal((await f.api(`/api/agents/${f.agent.id}/connect`, 'POST')).status, 503)
  f.setReady(true)
  await waitFor(async () => (await (await f.api('/api/agents')).json()).agents[0].online)
  const closed = new Promise(resolve => socket.once('close', resolve))
  assert.equal((await f.api(`/api/agents/${f.agent.id}/revoke`, 'POST')).status, 200)
  await closed
  assert.equal((await f.browser('/', { cookie })).status, 401)
  await waitFor(() => f.states.some(value => value.status === 'revoked'))
  listed = await (await f.api('/api/agents')).json()
  assert.equal(listed.agents[0].status, 'revoked')
  assert.equal(listed.agents[0].online, false)
  const persisted = fs.readFileSync(path.join(f.dir, 'server', 'managed-agents.json'), 'utf8')
  assert.ok(!persisted.includes(identity(path.join(f.dir, 'client.json')).secret))
  assert.equal((await f.api('/api/agents/enroll', 'POST', {
    id: f.agent.id, secret: crypto.randomBytes(32).toString('hex')
  }, false)).status, 409)
})

test('MCP grants are device/path/method scoped, stripped upstream, expire active SSE and revoke', { timeout: 15000 }, async t => {
  const f = await fixture(t, { sessionMs: 2000 })
  f.agent.start()
  await waitFor(() => f.states.some(value => value.status === 'pending'))
  await f.api(`/api/agents/${f.agent.id}/approve`, 'POST')
  await waitFor(async () => (await (await f.api('/api/agents')).json()).agents[0].online)
  const issued = await (await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST')).json()
  assert.match(issued.token, /^[a-f0-9]{64}$/)
  assert.equal(issued.url, `https://device-${f.agent.id.replace(/-/g, '')}.anubis.test/mcp`)
  assert.equal(issued.scope, 'mcp')
  const headers = { authorization: 'Bearer ' + issued.token }
  const response = await f.browser('/mcp?sessionId=fixture', {
    method: 'POST', headers, body: '{"jsonrpc":"2.0","method":"initialize","id":1}'
  })
  assert.equal(response.status, 200)
  assert.equal(response.body.toString(), '{"jsonrpc":"2.0","method":"initialize","id":1}')
  assert.equal(f.upstreamHeaders.at(-1).authorization, undefined)
  assert.equal(f.upstreamHeaders.at(-1)['x-anubis-managed-auth'], 'private-local-only')
  assert.equal((await f.browser('/mcp', { method: 'DELETE', headers })).status, 200)
  for (const route of ['/', '/api/get-constants', '/mcp/../api/get-constants', '/mcp/anything']) {
    assert.equal((await f.browser(route, { headers })).status, 401, route)
  }
  assert.equal((await f.browser('/mcp', { method: 'PUT', headers })).status, 401)
  assert.equal((await f.browser('/', { cookie: '__Host-anubis-gateway=' + issued.token })).status, 401)
  assert.equal((await f.browser('/mcp', {
    headers: { ...headers, host: `device-${crypto.randomUUID().replace(/-/g, '')}.anubis.test` }
  })).status, 401)
  assert.equal((await fetch(f.base + '/api/agents', { headers })).status, 401)
  assert.equal((await f.browser('/mcp', {
    headers: {
      ...headers,
      connection: 'Upgrade',
      upgrade: 'websocket',
      'sec-websocket-version': '13',
      'sec-websocket-key': crypto.randomBytes(16).toString('base64')
    }
  })).status, 401)
  const ended = new Promise((resolve, reject) => {
    const request = http.get(f.base + '/mcp?stream=1', {
      headers: { ...headers, host: new URL(issued.url).hostname }
    }, response => {
      assert.equal(response.statusCode, 200)
      response.on('data', () => {})
      response.once('aborted', resolve)
      response.once('end', () => reject(new Error('SSE ended without session expiration')))
    })
    request.once('error', reject)
  })
  await ended
  assert.ok(Date.now() >= issued.expiresAt)
  assert.equal((await f.browser('/mcp', { headers })).status, 401)
  const fresh = await (await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST')).json()
  assert.equal((await f.browser('/mcp', { headers: { authorization: 'Bearer ' + fresh.token } })).status, 200)
  await f.api(`/api/agents/${f.agent.id}/revoke`, 'POST')
  assert.equal((await f.browser('/mcp', { headers: { authorization: 'Bearer ' + fresh.token } })).status, 401)
})

test('MCP synchronous operations can respond beyond the ordinary 30-second Web header deadline', { timeout: 45000 }, async t => {
  const f = await fixture(t)
  f.agent.start()
  await waitFor(() => f.states.some(value => value.status === 'pending'))
  await f.api(`/api/agents/${f.agent.id}/approve`, 'POST')
  await waitFor(async () => (await (await f.api('/api/agents')).json()).agents[0].online)
  const issued = await (await f.api(`/api/agents/${f.agent.id}/mcp-token`, 'POST')).json()
  const connection = await (await f.api(`/api/agents/${f.agent.id}/connect`, 'POST')).json()
  const exchanged = await f.browser('/_anubis/connect', { method: 'POST', body: JSON.stringify({ ticket: connection.ticket }) })
  const cookie = exchanged.headers['set-cookie'][0].split(';')[0]
  const started = Date.now()
  const responses = await Promise.all([
    { headers: { authorization: 'Bearer ' + issued.token } },
    { cookie }
  ].map(credentials => f.browser('/mcp?delay=1', {
    ...credentials,
    method: 'POST',
    body: 'long synchronous MCP response',
    timeout: 40000
  })))
  for (const response of responses) {
    assert.equal(response.status, 200)
    assert.equal(response.body.toString(), 'long synchronous MCP response')
  }
  assert.ok(Date.now() - started >= 31000)
})
