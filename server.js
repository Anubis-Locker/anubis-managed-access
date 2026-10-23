'use strict'

const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const http = require('node:http')
const { WebSocketServer, WebSocket, createWebSocketStream } = require('ws')
const contextUi = require('./context-ui')

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digest = value => crypto.createHash('sha256').update(value).digest('hex')
const equal = (left, right) => typeof left === 'string' && typeof right === 'string' &&
  left.length === right.length && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right))

function json (res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
  res.end(JSON.stringify(value))
  return true
}

async function body (req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > 32768) throw Object.assign(new Error('Request body too large'), { status: 413 })
    chunks.push(chunk)
  }
  try { return JSON.parse(Buffer.concat(chunks).toString()) } catch {
    throw Object.assign(new Error('Invalid JSON'), { status: 400 })
  }
}

function createGateway ({
  dataDir, isAdmin, domain = 'anubis.locker', sessionMs = 8 * 60 * 60 * 1000,
  channelTimeout = 10000, presenceMs = 45000, maxAgents = 1000, maxChannels = 256
}) {
  if (!/^[a-z0-9.-]+$/.test(domain)) throw new Error('Invalid managed gateway domain')
  fs.mkdirSync(dataDir, { recursive: true })
  const file = path.join(dataDir, 'managed-agents.json')
  let saved = {}
  try { saved = JSON.parse(fs.readFileSync(file, 'utf8')) } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (!saved || typeof saved !== 'object' || Array.isArray(saved)) throw new Error('Invalid managed agent database')
  for (const [id, value] of Object.entries(saved)) {
    if (!uuid.test(id) || !/^[0-9a-f]{64}$/.test(value.fingerprint) ||
        !['pending', 'approved', 'revoked'].includes(value.status)) {
      throw new Error('Invalid managed agent database entry')
    }
  }
  const agents = new Map(Object.entries(saved))
  const controls = new Map()
  const pending = new Map()
  const streams = new Map()
  const tickets = new Map()
  const sessions = new Map()
  const registrations = new Map()
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 })
  let closed = false

  function persist () {
    const next = file + '.next'
    fs.writeFileSync(next, JSON.stringify(Object.fromEntries(agents)), { mode: 0o600 })
    fs.renameSync(next, file)
  }

  function origin (id) {
    return `https://device-${id.replace(/-/g, '')}.${domain}`
  }

  function hostId (req) {
    const host = (req.headers.host || '').toLowerCase().split(':')[0]
    const suffix = '.' + domain
    if (!host.endsWith(suffix)) return
    const value = host.slice(0, -suffix.length)
    if (!/^device-[0-9a-f]{32}$/.test(value)) return
    const raw = value.slice(7)
    return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`
  }

  function authenticate (req, id) {
    const value = agents.get(id)
    const authorization = req.headers.authorization
    if (!value || typeof authorization !== 'string' || !/^Bearer [0-9a-f]{64}$/.test(authorization)) return
    if (equal(digest(authorization.slice(7)), value.fingerprint)) return value
  }

  function publicAgent (id, agent) {
    const live = controls.get(id)
    const online = agent.status === 'approved' && live?.ready === true &&
      live.ws.readyState === WebSocket.OPEN && Date.now() - live.lastSeen < presenceMs
    return {
      id,
      label: agent.label,
      app: agent.app,
      version: agent.version,
      platform: agent.platform,
      arch: agent.arch,
      status: agent.status,
      fingerprint: agent.fingerprint,
      createdAt: agent.createdAt,
      online,
      lastSeen: live?.lastSeen || null,
      url: online ? origin(id) : undefined
    }
  }

  function operator (req, id, upgrade = false) {
    const cookie = (req.headers.cookie || '').split(';').map(value => value.trim())
      .find(value => value.startsWith('__Host-anubis-gateway='))
    const key = cookie?.slice('__Host-anubis-gateway='.length)
    const bearerKey = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.authorization || '')?.[1]
    const bearer = sessions.get(bearerKey)
    const session = bearer?.scope === 'mcp' ? bearer : sessions.get(key)
    if (!session || session.id !== id || session.expiresAt <= Date.now() ||
        agents.get(id)?.status !== 'approved') return
    if (session.scope === 'mcp' && (upgrade ||
        new URL(req.url, 'http://localhost').pathname !== '/mcp' ||
        !['GET', 'POST', 'DELETE'].includes(req.method))) return
    return session
  }

  function headers (req, upgrade = false, session) {
    const result = { ...req.headers }
    if (session?.scope === 'mcp') delete result.authorization
    const reserved = ['proxy-authorization', 'proxy-authenticate', 'x-anubis-managed-auth',
      'x-anubis-managed-session', 'x-anubis-managed-context',
      'forwarded', 'x-forwarded-host', 'x-forwarded-for', 'x-forwarded-proto']
    for (const name of reserved) delete result[name]
    if (session?.scope === 'web') {
      result['x-anubis-managed-session'] = session.bindingId
      if (session.selector) result['x-anubis-managed-context'] = session.selector
    }
    if (result.cookie) {
      result.cookie = result.cookie.split(';').filter(value =>
        !value.trim().startsWith('__Host-anubis-gateway=')).join(';')
      if (!result.cookie) delete result.cookie
    }
    if (!upgrade) {
      for (const name of ['connection', 'upgrade', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding']) delete result[name]
      result.connection = 'close'
    }
    return result
  }

  function connect (id) {
    const live = controls.get(id)
    if (!live || !publicAgent(id, agents.get(id)).online) {
      return Promise.reject(Object.assign(new Error('Managed Web endpoint is offline'), { status: 503 }))
    }
    if (pending.size + streams.size >= maxChannels) {
      return Promise.reject(Object.assign(new Error('Managed gateway is busy'), { status: 503 }))
    }
    return new Promise((resolve, reject) => {
      const channelId = crypto.randomUUID()
      const timeout = setTimeout(() => {
        pending.delete(channelId)
        reject(Object.assign(new Error('Managed channel timed out'), { status: 504 }))
      }, channelTimeout)
      timeout.unref?.()
      pending.set(channelId, { id, resolve, reject, timeout })
      live.ws.send(JSON.stringify({ type: 'open', channelId }), error => {
        if (!error) return
        clearTimeout(timeout)
        pending.delete(channelId)
        reject(error)
      })
    })
  }

  function request (req, stream, upgrade = false, session) {
    return http.request({
      hostname: 'managed.local',
      port: 80,
      path: req.url,
      method: req.method,
      headers: headers(req, upgrade, session),
      createConnection: () => stream
    })
  }

  function track (session, stream) {
    session.channels ||= new Set()
    session.channels.add(stream)
    stream.once('close', () => session.channels.delete(stream))
  }

  function closeSessionChannels (session) {
    session.generation = (session.generation || 0) + 1
    for (const stream of session.channels || []) stream.destroy()
    session.channels?.clear()
  }

  function identity (value, full = false) {
    if (!value || !/^S-1-(?:\d+-)+\d+$/.test(value.sid) ||
        typeof value.account !== 'string' || !value.account || value.account.length > 256 ||
        !Number.isSafeInteger(value.sessionId) || value.sessionId < 0 ||
        (full && (typeof value.elevated !== 'boolean' || !Number.isSafeInteger(value.pid) || value.pid < 1))) {
      throw Object.assign(new Error('Invalid Windows context response'), { status: 502 })
    }
    return {
      sid: value.sid,
      account: value.account,
      sessionId: value.sessionId,
      ...(full ? { elevated: value.elevated, pid: value.pid } : {})
    }
  }

  async function machineContexts (id, session, method, input) {
    const generation = session.generation
    const stream = await connect(id)
    if (session.generation !== generation || session.expiresAt <= Date.now()) {
      stream.destroy()
      throw Object.assign(new Error('Managed access changed or expired'), { status: 401 })
    }
    track(session, stream)
    return new Promise((resolve, reject) => {
      const payload = input ? JSON.stringify(input) : ''
      const upstream = http.request({
        hostname: 'managed.local',
        port: 80,
        path: '/api/machine-contexts',
        method,
        headers: {
          'x-anubis-managed-session': session.bindingId,
          connection: 'close',
          ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {})
        },
        createConnection: () => stream
      }, remote => {
        const chunks = []
        let size = 0
        remote.on('data', chunk => {
          size += chunk.length
          if (size > 65536) return upstream.destroy(new Error('Windows context response is too large'))
          chunks.push(chunk)
        })
        remote.once('error', reject)
        remote.once('end', () => {
          if (remote.statusCode !== 200) {
            return reject(Object.assign(new Error('Windows contexts are unavailable'), {
              status: [400, 403, 404, 409, 429, 501, 503, 504].includes(remote.statusCode) ? remote.statusCode : 502
            }))
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString()))
          } catch {
            reject(Object.assign(new Error('Invalid Windows context response'), { status: 502 }))
          }
        })
      })
      const timeout = setTimeout(() => upstream.destroy(new Error('Windows context operation timed out')), 45000)
      timeout.unref?.()
      upstream.once('close', () => clearTimeout(timeout))
      upstream.once('error', reject)
      upstream.end(payload)
    })
  }

  async function contextControl (req, res, id) {
    const session = operator(req, id)
    if (!session || session.scope !== 'web') return json(res, 401, { error: 'Authenticated browser access required' })
    if (req.method !== 'GET' && req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' })
    try {
      if (req.method === 'GET') {
        let result
        try { result = await machineContexts(id, session, 'GET') } catch (error) {
          if ([404, 501].includes(error.status)) return json(res, 200, { supported: false, contexts: [] })
          throw error
        }
        if (result?.supported !== true || !Array.isArray(result.contexts) || result.contexts.length > 128) {
          throw Object.assign(new Error('Invalid Windows context list'), { status: 502 })
        }
        const contexts = result.contexts.map(value => {
          if (!/^[a-f0-9]{32}$/.test(value?.id) || !['system', 'user'].includes(value.target)) {
            throw Object.assign(new Error('Invalid Windows context choice'), { status: 502 })
          }
          return { id: value.id, target: value.target, identity: identity(value.identity) }
        })
        const system = contexts.find(value => value.target === 'system')
        const current = session.context || system
        return json(res, 200, { supported: true, contexts, current, selectedId: session.choiceId || system?.id })
      }
      if (req.headers.origin !== origin(id) ||
          !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) {
        return json(res, 403, { error: 'Same-origin JSON request required' })
      }
      const input = await body(req)
      if (!input || Object.keys(input).length !== 1 || !/^[a-f0-9]{32}$/.test(input.id)) {
        return json(res, 400, { error: 'A listed Windows context is required' })
      }
      if (session.selecting) return json(res, 409, { error: 'A Windows context change is already in progress' })
      session.selecting = true
      try {
        const result = await machineContexts(id, session, 'POST', input)
        if (!/^[a-f0-9]{32}$/.test(result?.selector) ||
            !/^[a-f0-9]{32}$/.test(result.context?.contextId)) {
          throw Object.assign(new Error('Invalid Windows context selection'), { status: 502 })
        }
        const context = { contextId: result.context.contextId, identity: identity(result.context.identity, true) }
        if (session.expiresAt <= Date.now() || agents.get(id)?.status !== 'approved' ||
            sessions.get(session.key) !== session) {
          return json(res, 401, { error: 'Managed access changed or expired' })
        }
        closeSessionChannels(session)
        sessions.delete(session.key)
        session.key = crypto.randomBytes(32).toString('hex')
        session.selector = result.selector
        session.context = context
        session.choiceId = input.id
        sessions.set(session.key, session)
        res.setHeader('set-cookie', browserCookie(session))
        return json(res, 200, { ok: true, context })
      } finally {
        session.selecting = false
      }
    } catch (error) {
      if (!error.status) console.warn('Managed context operation failed:', error.message)
      return json(res, error.status || 502, { error: error.status ? error.message : 'Windows context operation failed' })
    }
  }

  function browserCookie (session) {
    const seconds = Math.max(1, Math.floor((session.expiresAt - Date.now()) / 1000))
    return `__Host-anubis-gateway=${session.key}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${seconds}`
  }

  async function proxy (req, res, id) {
    const session = operator(req, id)
    if (!session) return json(res, 401, { error: 'Open this device from the administrator panel' })
    const generation = session.generation
    let upstream
    try {
      const stream = await connect(id)
      if (session.expiresAt <= Date.now() || session.generation !== generation) {
        stream.destroy()
        return json(res, 401, { error: 'Managed access expired' })
      }
      track(session, stream)
      upstream = request(req, stream, false, session)
      const expiration = setTimeout(() => upstream.destroy(
        Object.assign(new Error('Managed access expired'), { status: 401 })
      ), session.expiresAt - Date.now())
      expiration.unref?.()
      const timeoutMs = new URL(req.url, 'http://localhost').pathname === '/mcp' ? 130000 : 30000
      const timeout = setTimeout(() => upstream.destroy(new Error('Managed response timed out')), timeoutMs)
      timeout.unref?.()
      upstream.once('response', remote => {
        clearTimeout(timeout)
        const responseHeaders = { ...remote.headers, 'cache-control': 'no-store' }
        delete responseHeaders['content-security-policy-report-only']
        if (responseHeaders['set-cookie']) {
          responseHeaders['set-cookie'] = responseHeaders['set-cookie'].filter(value =>
            !/^__Host-anubis-gateway=/i.test(value))
        }
        res.writeHead(remote.statusCode, responseHeaders)
        remote.on('error', error => res.destroy(error))
        remote.pipe(res)
      })
      upstream.once('error', error => {
        clearTimeout(timeout)
        if (!res.headersSent) json(res, error.status || 502, { error: error.status === 401 ? error.message : 'Managed upstream connection failed' })
        else res.destroy(error)
      })
      req.once('aborted', () => upstream.destroy())
      res.once('close', () => {
        clearTimeout(expiration)
        upstream.destroy()
      })
      req.pipe(upstream)
    } catch (error) {
      if (!res.headersSent) json(res, error.status || 502, { error: error.message })
      else res.destroy(error)
    }
  }

  async function handle (req, res) {
    const url = new URL(req.url, 'http://localhost')
    const id = hostId(req)
    if (id) {
      let pathname
      try { pathname = decodeURIComponent(url.pathname).replace(/\/+$/, '') } catch {
        return json(res, 400, { error: 'Invalid managed path encoding' })
      }
      if (pathname === '/api/machine-contexts') {
        return json(res, 403, { error: 'Use the authenticated managed context controls' })
      }
      if (url.pathname === '/_anubis/contexts') return contextControl(req, res, id)
      if (['/_anubis/context-ui.js', '/_anubis/context-ui.css'].includes(url.pathname)) {
        const session = operator(req, id)
        if (!session || session.scope !== 'web') return json(res, 401, { error: 'Authenticated browser access required' })
        if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' })
        const script = url.pathname.endsWith('.js')
        res.writeHead(200, {
          'content-type': script ? 'application/javascript; charset=utf-8' : 'text/css; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff'
        })
        res.end(script ? contextUi.script : contextUi.style)
        return true
      }
      if (url.pathname === '/_anubis/connect' && req.method === 'POST') {
        try {
          const input = await body(req)
          const ticket = tickets.get(input.ticket)
          tickets.delete(input.ticket)
          if (!ticket || ticket.id !== id || ticket.expiresAt <= Date.now() ||
              agents.get(id)?.status !== 'approved') return json(res, 401, { error: 'Invalid or expired connection ticket' })
          const key = crypto.randomBytes(32).toString('hex')
          const session = {
            id,
            key,
            scope: 'web',
            expiresAt: Date.now() + sessionMs,
            bindingId: crypto.randomBytes(32).toString('hex'),
            generation: 0,
            channels: new Set()
          }
          sessions.set(key, session)
          res.writeHead(200, {
            'content-type': 'application/json',
            'cache-control': 'no-store',
            'set-cookie': browserCookie(session),
            'access-control-allow-origin': `https://api.${domain}`,
            'access-control-allow-credentials': 'true',
            vary: 'Origin'
          })
          res.end('{"ok":true}')
        } catch (error) {
          json(res, error.status || 500, { error: error.status ? error.message : 'Connection ticket exchange failed' })
        }
      } else if (url.pathname === '/_anubis/connect' && req.method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-origin': `https://api.${domain}`,
          'access-control-allow-credentials': 'true',
          'access-control-allow-methods': 'POST',
          'access-control-allow-headers': 'content-type',
          vary: 'Origin'
        })
        res.end()
      } else await proxy(req, res, id)
      return true
    }
    if (!url.pathname.startsWith('/api/agents')) return false
    try {
      if (url.pathname === '/api/agents/enroll' && req.method === 'POST') {
        const input = await body(req)
        if (!uuid.test(input?.id) || !/^[0-9a-f]{64}$/.test(input?.secret)) {
          return json(res, 400, { error: 'Valid installation UUID and secret required' })
        }
        const existing = agents.get(input.id)
        if (existing && !equal(existing.fingerprint, digest(input.secret))) {
          return json(res, 409, { error: 'Installation identity already registered with another credential' })
        }
        if (!existing) {
          const ip = req.socket.remoteAddress
          const quota = registrations.get(ip) || { count: 0, start: Date.now() }
          if (Date.now() - quota.start > 3600000) { quota.count = 0; quota.start = Date.now() }
          if (agents.size >= maxAgents || quota.count >= 60) return json(res, 429, { error: 'Enrollment limit reached' })
          quota.count++
          registrations.set(ip, quota)
          const value = { status: 'pending', fingerprint: digest(input.secret), createdAt: Date.now() }
          for (const field of ['label', 'app', 'version', 'platform', 'arch']) {
            value[field] = typeof input[field] === 'string' ? input[field].slice(0, 128) : ''
          }
          agents.set(input.id, value)
          try { persist() } catch (error) { agents.delete(input.id); throw error }
        } else {
          const updated = { ...existing }
          for (const field of ['label', 'app', 'version', 'platform', 'arch']) {
            if (typeof input[field] === 'string') updated[field] = input[field].slice(0, 128)
          }
          if (JSON.stringify(updated) !== JSON.stringify(existing)) {
            agents.set(input.id, updated)
            try { persist() } catch (error) { agents.set(input.id, existing); throw error }
          }
        }
        const agent = agents.get(input.id)
        return json(res, existing ? 200 : 201, {
          id: input.id,
          status: agent.status,
          fingerprint: agent.fingerprint,
          url: agent.status === 'approved' ? origin(input.id) : undefined
        })
      }
      if (!isAdmin(req)) return json(res, 401, { error: 'unauthorized' })
      if (url.pathname === '/api/agents' && req.method === 'GET') {
        return json(res, 200, { agents: [...agents].map(([id, value]) => publicAgent(id, value)) })
      }
      const match = url.pathname.match(/^\/api\/agents\/([0-9a-f-]{36})\/(approve|revoke|connect|mcp-token)$/)
      const agent = match && agents.get(match[1])
      if (!agent || req.method !== 'POST') return json(res, 404, { error: 'not found' })
      const [, agentId, action] = match
      if (action === 'mcp-token') {
        if (!publicAgent(agentId, agent).online) return json(res, 503, { error: 'Managed endpoint is not online' })
        const token = crypto.randomBytes(32).toString('hex')
        const expiresAt = Date.now() + Math.min(sessionMs, 60 * 60 * 1000)
        sessions.set(token, { id: agentId, scope: 'mcp', expiresAt })
        return json(res, 200, { url: origin(agentId) + '/mcp', token, scope: 'mcp', expiresAt })
      }
      if (action === 'connect') {
        if (!publicAgent(agentId, agent).online) return json(res, 503, { error: 'Managed endpoint is not online' })
        const ticket = crypto.randomBytes(32).toString('hex')
        tickets.set(ticket, { id: agentId, expiresAt: Date.now() + 30000 })
        return json(res, 200, { url: origin(agentId), ticket, expiresAt: Date.now() + 30000 })
      }
      const previous = agent.status
      agent.status = action === 'approve' ? 'approved' : 'revoked'
      try { persist() } catch (error) { agent.status = previous; throw error }
      if (action === 'revoke') {
        controls.get(agentId)?.ws.close(1008, 'Access revoked')
        for (const [key, session] of sessions) {
          if (session.id !== agentId) continue
          closeSessionChannels(session)
          sessions.delete(key)
        }
        for (const [key, ticket] of tickets) if (ticket.id === agentId) tickets.delete(key)
        for (const value of streams.values()) if (value.id === agentId) value.ws.terminate()
      }
      return json(res, 200, publicAgent(agentId, agent))
    } catch (error) {
      if (!error.status) console.error('Managed gateway request failed:', error.message)
      json(res, error.status || 500, { error: error.status ? error.message : 'Managed gateway storage unavailable' })
      return true
    }
  }

  async function upgrade (req, socket, head) {
    const reject = code => {
      socket.end(`HTTP/1.1 ${code} Error\r\nConnection: close\r\n\r\n`)
    }
    const id = hostId(req)
    if (id) {
      const session = operator(req, id, true)
      if (!session) return reject(401)
      const generation = session.generation
      try {
        const stream = await connect(id)
        if (session.expiresAt <= Date.now() || session.generation !== generation) {
          stream.destroy()
          return reject(401)
        }
        track(session, stream)
        const remote = request(req, stream, true, session)
        remote.once('upgrade', (response, upstream, extra) => {
          let header = `HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n`
          for (let index = 0; index < response.rawHeaders.length; index += 2) {
            header += response.rawHeaders[index] + ': ' + response.rawHeaders[index + 1] + '\r\n'
          }
          socket.write(header + '\r\n')
          if (extra.length) socket.write(extra)
          if (head.length) upstream.write(head)
          upstream.on('error', () => socket.destroy())
          socket.on('error', () => upstream.destroy())
          socket.once('close', () => upstream.destroy())
          upstream.once('close', () => socket.destroy())
          const timeout = setTimeout(() => socket.destroy(), session.expiresAt - Date.now())
          timeout.unref?.()
          socket.once('close', () => clearTimeout(timeout))
          upstream.pipe(socket).pipe(upstream)
        })
        remote.once('response', () => { remote.destroy(); reject(502) })
        remote.once('error', () => reject(502))
        socket.once('close', () => remote.destroy())
        remote.end()
      } catch { reject(503) }
      return
    }
    const route = new URL(req.url, 'http://localhost').pathname
    const match = route.match(/^\/api\/agents\/([0-9a-f-]{36})\/(tunnel|channels\/([0-9a-f-]{36}))$/)
    const agent = match && authenticate(req, match[1])
    if (!agent || agent.status !== 'approved') return reject(401)
    const [, agentId, action, channelId] = match
    const channel = channelId && pending.get(channelId)
    if (channelId && (!channel || channel.id !== agentId)) return reject(404)
    wss.handleUpgrade(req, socket, head, ws => {
      ws.on('error', error => console.warn('Managed transport error:', error.message))
      if (action !== 'tunnel') {
        clearTimeout(channel.timeout)
        pending.delete(channelId)
        streams.set(channelId, { id: agentId, ws })
        ws.once('close', () => streams.delete(channelId))
        const stream = createWebSocketStream(ws)
        stream.on('error', error => console.warn('Managed stream error:', error.message))
        stream.setNoDelay = () => stream
        stream.setKeepAlive = () => stream
        channel.resolve(stream)
        return
      }
      controls.get(agentId)?.ws.close(1008, 'Replaced by a new authenticated connection')
      const live = { ws, ready: false, lastSeen: Date.now() }
      controls.set(agentId, live)
      ws.send(JSON.stringify({ type: 'welcome', url: origin(agentId) }))
      ws.on('pong', () => { live.lastSeen = Date.now() })
      ws.on('message', message => {
        try {
          const value = JSON.parse(message.toString())
          if (value.type !== 'status' || typeof value.ready !== 'boolean') return ws.close(1002)
          live.ready = value.ready
          live.lastSeen = Date.now()
        } catch { ws.close(1002) }
      })
      ws.once('close', () => {
        if (controls.get(agentId) !== live) return
        controls.delete(agentId)
        for (const [key, value] of pending) {
          if (value.id !== agentId) continue
          clearTimeout(value.timeout)
          pending.delete(key)
          value.reject(Object.assign(new Error('Managed endpoint disconnected'), { status: 503 }))
        }
        for (const value of streams.values()) if (value.id === agentId) value.ws.terminate()
      })
    })
  }

  const cleanup = setInterval(() => {
    const now = Date.now()
    for (const [key, value] of tickets) if (value.expiresAt <= now) tickets.delete(key)
    for (const [key, value] of sessions) {
      if (value.expiresAt > now) continue
      closeSessionChannels(value)
      sessions.delete(key)
    }
    for (const live of controls.values()) {
      if (now - live.lastSeen > presenceMs) live.ws.terminate()
      else live.ws.ping()
    }
  }, Math.min(15000, presenceMs))
  cleanup.unref?.()

  return {
    handle,
    upgrade,
    async close () {
      if (closed) return
      closed = true
      clearInterval(cleanup)
      for (const value of pending.values()) {
        clearTimeout(value.timeout)
        value.reject(new Error('Managed gateway stopped'))
      }
      pending.clear()
      for (const live of controls.values()) live.ws.terminate()
      for (const value of streams.values()) value.ws.terminate()
      for (const ws of wss.clients) ws.terminate()
      controls.clear()
      streams.clear()
      sessions.clear()
      tickets.clear()
      await new Promise(resolve => wss.close(resolve))
    }
  }
}

module.exports = { createGateway }
