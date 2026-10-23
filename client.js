'use strict'

const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const net = require('node:net')
const { WebSocket, createWebSocketStream } = require('ws')

function identity (file) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  try {
    const value = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id) || !/^[0-9a-f]{64}$/.test(value.secret)) {
      throw new Error('Invalid managed installation identity')
    }
    return value
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    const value = { id: crypto.randomUUID(), secret: crypto.randomBytes(32).toString('hex') }
    try {
      fs.writeFileSync(file, JSON.stringify(value), { flag: 'wx', mode: 0o600 })
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
      return identity(file)
    }
    return value
  }
}

function createAgent (options) {
  const {
    baseUrl, identityFile, label = 'Anubis', app = 'anubis',
    version = '', localHost = '127.0.0.1', localPort,
    probe = async () => true, onStatus = () => {}, localHeaders = {},
    reconnectMs = 5000, heartbeatMs = 15000
  } = options
  const base = new URL(baseUrl)
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname))) {
    throw new Error('Managed API must use HTTPS')
  }
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/') {
    throw new Error('Managed API must be a credential-free origin')
  }
  if (!['127.0.0.1', '::1', 'localhost'].includes(localHost) ||
      !Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    throw new Error('Managed upstream must be a fixed loopback HTTP port')
  }
  for (const [name, value] of Object.entries(localHeaders)) {
    if (!/^[a-z0-9-]+$/i.test(name) || /[\r\n]/.test(String(value))) throw new Error('Invalid managed local header')
  }
  const saved = identity(identityFile)
  const fingerprint = crypto.createHash('sha256').update(saved.secret).digest('hex')
  const sockets = new Set()
  const abort = new AbortController()
  let control
  let retry
  let pulse
  let running = false
  let probing = false
  let state = 'offline'
  let url

  function status (next, error) {
    state = next
    onStatus({ id: saved.id, status: next, fingerprint, url: next === 'online' ? url : undefined, error })
  }

  function websocket (route) {
    const target = new URL(route, base)
    target.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(target, {
      headers: { Authorization: 'Bearer ' + saved.secret },
      handshakeTimeout: 10000,
      maxPayload: 1024 * 1024
    })
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
    return socket
  }

  function channel (channelId) {
    if (!/^[0-9a-f-]{36}$/.test(channelId)) return status('offline', 'Invalid managed channel identifier')
    const socket = websocket(`/api/agents/${saved.id}/channels/${channelId}`)
    let local
    socket.once('open', () => {
      if (!running) return socket.close()
      const stream = createWebSocketStream(socket)
      local = net.createConnection({ host: localHost, port: localPort })
      local.once('error', error => {
        status('offline', 'Managed local connection failed: ' + error.message)
        stream.destroy()
      })
      stream.once('error', error => {
        status('offline', 'Managed channel failed: ' + error.message)
        local.destroy()
      })
      stream.once('close', () => local.destroy())
      local.once('close', () => stream.destroy())
      local.pipe(stream)
      if (!Object.keys(localHeaders).length) return stream.pipe(local)
      let header = Buffer.alloc(0)
      const first = chunk => {
        header = Buffer.concat([header, chunk])
        const end = header.indexOf('\r\n\r\n')
        if (end < 0) {
          if (header.length > 65536) stream.destroy(new Error('Managed HTTP header too large'))
          return
        }
        stream.pause()
        stream.removeListener('data', first)
        const names = new Set(Object.keys(localHeaders).map(name => name.toLowerCase()))
        const lines = header.subarray(0, end).toString('latin1').split('\r\n')
        const start = lines.shift()
        const retained = lines.filter(line => !names.has(line.split(':', 1)[0].toLowerCase()))
        for (const [name, value] of Object.entries(localHeaders)) retained.push(`${name}: ${value}`)
        local.write([start, ...retained, '', ''].join('\r\n'), 'latin1')
        const remainder = header.subarray(end + 4)
        if (remainder.length) local.write(remainder)
        header = null
        stream.pipe(local)
        stream.resume()
      }
      stream.on('data', first)
    })
    socket.once('error', error => status('offline', 'Managed channel connection failed: ' + error.message))
  }

  async function health () {
    if (!running || probing || control?.readyState !== WebSocket.OPEN) return
    probing = true
    try {
      const ready = await probe()
      if (!running || control?.readyState !== WebSocket.OPEN) return
      control.send(JSON.stringify({ type: 'status', ready: ready === true }))
      status(ready === true ? 'online' : 'offline', ready === true ? undefined : 'Local Web endpoint is not ready')
    } catch (error) {
      if (control?.readyState === WebSocket.OPEN) control.send(JSON.stringify({ type: 'status', ready: false }))
      if (running) status('offline', 'Managed readiness probe failed: ' + error.message)
    } finally {
      probing = false
    }
  }

  function schedule () {
    clearTimeout(retry)
    if (running) retry = setTimeout(connect, reconnectMs)
    retry?.unref?.()
  }

  async function connect () {
    if (!running) return
    try {
      const response = await fetch(new URL('/api/agents/enroll', base), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        redirect: 'error',
        signal: AbortSignal.any([abort.signal, AbortSignal.timeout(10000)]),
        body: JSON.stringify({
          ...saved, label, app, version, platform: process.platform, arch: process.arch
        })
      })
      if (!response.ok) throw new Error('Enrollment rejected: HTTP ' + response.status)
      const enrollment = await response.json()
      if (!running) return
      if (enrollment.id !== saved.id || !['pending', 'approved', 'revoked'].includes(enrollment.status)) {
        throw new Error('Invalid managed enrollment response')
      }
      url = enrollment.url
      if (enrollment.status !== 'approved') {
        status(enrollment.status)
        return schedule()
      }
      control = websocket(`/api/agents/${saved.id}/tunnel`)
      control.on('message', data => {
        try {
          const message = JSON.parse(data.toString())
          if (message.type === 'open') channel(message.channelId)
          else if (message.type === 'welcome') {
            url = message.url
            health()
          }
        } catch (error) {
          status('offline', 'Invalid managed control message: ' + error.message)
          control.close(1002)
        }
      })
      control.once('open', () => {
        pulse = setInterval(health, heartbeatMs)
        pulse.unref?.()
      })
      control.once('error', error => {
        if (running) status('offline', 'Managed tunnel failed: ' + error.message)
      })
      control.once('close', () => {
        clearInterval(pulse)
        for (const socket of sockets) if (socket !== control) socket.terminate()
        if (running) {
          status('offline', 'Managed tunnel disconnected')
          schedule()
        }
      })
    } catch (error) {
      if (!running) return
      status('offline', error.message)
      schedule()
    }
  }

  return {
    get id () { return saved.id },
    get fingerprint () { return fingerprint },
    get status () { return state },
    start () {
      if (abort.signal.aborted) throw new Error('Stopped managed agent cannot be restarted')
      if (running) return
      running = true
      connect()
    },
    async stop () {
      running = false
      clearTimeout(retry)
      clearInterval(pulse)
      abort.abort()
      for (const socket of sockets) socket.terminate()
      sockets.clear()
      status('offline')
    }
  }
}

module.exports = { createAgent, identity }
