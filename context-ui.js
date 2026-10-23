'use strict'

function contextUi () {
  if (document.getElementById('anubis-context-controls')) return
  const link = document.createElement('link')
  link.rel = 'stylesheet'
  link.href = '/_anubis/context-ui.css'
  document.head.appendChild(link)
  const bar = document.createElement('div')
  bar.id = 'anubis-context-controls'
  bar.setAttribute('role', 'region')
  bar.setAttribute('aria-label', 'Windows workspace')
  const label = document.createElement('label')
  label.textContent = 'Windows workspace: '
  const select = document.createElement('select')
  select.setAttribute('aria-label', 'Windows workspace')
  select.disabled = true
  label.appendChild(select)
  const refresh = document.createElement('button')
  refresh.textContent = 'Refresh'
  const status = document.createElement('span')
  status.setAttribute('role', 'status')
  bar.append(label, refresh, status)
  document.body.prepend(bar)
  document.body.classList.add('anubis-managed-contexts')
  let currentId = ''
  let changing = false
  async function request (method = 'GET', payload) {
    const response = await fetch('/_anubis/contexts', {
      method,
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
      signal: AbortSignal.timeout(50000),
      ...(payload ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) } : {})
    })
    const result = await response.json()
    if (!response.ok) throw new Error(result.error || 'HTTP ' + response.status)
    return result
  }
  function describe (value) {
    const identity = value.identity
    return identity.account + ' | ' + identity.sid + ' | session ' + identity.sessionId
  }
  async function load () {
    select.disabled = true
    refresh.disabled = true
    status.textContent = 'Loading Windows contexts...'
    try {
      const result = await request()
      if (!result.supported) throw new Error('This host does not support remote Windows context selection')
      select.replaceChildren()
      for (const choice of result.contexts) {
        const option = document.createElement('option')
        option.value = choice.id
        option.textContent = describe(choice)
        select.appendChild(option)
      }
      const selected = result.contexts.find(choice => choice.id === result.selectedId)
      currentId = selected?.id || ''
      if (!currentId) {
        const unavailable = document.createElement('option')
        unavailable.value = ''
        unavailable.textContent = 'Selected Windows context is unavailable'
        unavailable.disabled = true
        select.prepend(unavailable)
      }
      select.value = currentId
      status.textContent = result.current
        ? describe(result.current) + (currentId ? '' : ' (unavailable; choose another context explicitly)')
        : 'Choose a Windows context'
      select.disabled = false
    } catch (error) {
      status.textContent = 'Windows contexts: ' + error.message
    } finally {
      refresh.disabled = false
    }
  }
  refresh.addEventListener('click', () => { if (!changing) load() })
  select.addEventListener('change', async () => {
    if (changing || !select.value || select.value === currentId) return
    if (!window.confirm('Switch this browser session to ' + select.selectedOptions[0].textContent +
        '? Existing connections in this browser session will close. The selected Windows profile keeps its own password and data.')) {
      select.value = currentId
      return
    }
    changing = true
    select.disabled = true
    refresh.disabled = true
    status.textContent = 'Changing Windows context...'
    try {
      await request('POST', { id: select.value })
      window.localStorage.removeItem('tokenElecterm')
      window.location.reload()
    } catch (error) {
      status.textContent = 'Windows context change failed: ' + error.message + '. Refresh before retrying.'
      refresh.disabled = false
    } finally {
      changing = false
    }
  })
  load()
}

module.exports = {
  script: '(' + contextUi.toString() + ')();',
  style: `
#anubis-context-controls {
  position: fixed; inset: 0 0 auto 0; z-index: 10000; min-height: 42px;
  display: flex; align-items: center; gap: 10px; padding: 6px 10px;
  box-sizing: border-box; color: #e6edf3; background: #17191d;
  border-bottom: 1px solid #475366; font: 12px system-ui, sans-serif;
}
#anubis-context-controls select { max-width: 48vw; }
#anubis-context-controls [role="status"] { overflow-wrap: anywhere; }
body.anubis-managed-contexts #container { margin-top: 54px; height: calc(100vh - 54px); }
@media (max-width: 700px) {
  #anubis-context-controls { flex-wrap: wrap; }
  #anubis-context-controls [role="status"] { display: none; }
  #anubis-context-controls select { max-width: 65vw; }
}
`
}
