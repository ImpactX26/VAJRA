const VAJRA = 'http://127.0.0.1:8001'

const $ = (id) => document.getElementById(id)

function setRow(id, state, value) {
  const row = $(id)
  row.className = `row ${state}`
  row.querySelector('.value').textContent = value
}

async function json(path) {
  const r = await fetch(`${VAJRA}${path}`, { cache: 'no-store' })
  if (!r.ok) throw new Error(r.status)
  return r.json()
}

async function loadStatus() {
  try {
    await json('/api/status')
    setRow('st-server', 'ok', 'online')
  } catch {
    setRow('st-server', 'bad', 'offline: downloads blocked')
    setRow('st-test', '', 'unavailable')
    setRow('st-pdf', '', 'unavailable')
    return
  }
  json('/api/selftest?quiet=1')
    .then((t) => setRow('st-test', t.ok ? 'ok' : 'bad', `${t.passed}/${t.total} passing`))
    .catch(() => setRow('st-test', 'warn', 'unavailable'))
  json('/api/convert/status')
    .then((s) => setRow('st-pdf', s.ilovepdf ? 'ok' : 'warn', s.ilovepdf ? 'connected' : 'key missing'))
    .catch(() => setRow('st-pdf', 'warn', 'unavailable'))
}

function ago(t) {
  const s = Math.round((Date.now() - t) / 1000)
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`
}

async function loadHistory() {
  const { history = [], counts = {}, enabled = true } = await chrome.storage.local.get(['history', 'counts', 'enabled'])
  $('enabled').checked = enabled
  for (const k of ['checked', 'delivered', 'burned', 'blocked']) $(`c-${k}`).textContent = counts[k] || 0
  const list = $('history')
  if (!history.length) return
  list.replaceChildren(...history.map((h) => {
    const li = document.createElement('li')
    li.className = h.verdict
    const top = document.createElement('div')
    top.className = 'top'
    const name = document.createElement('span')
    name.className = 'name'
    name.textContent = h.name
    name.title = h.name
    const verdict = document.createElement('span')
    verdict.className = 'verdict'
    verdict.textContent = h.verdict
    top.append(name, verdict)
    const why = document.createElement('span')
    why.className = 'why'
    why.textContent = `${h.source} · ${ago(h.time)}${h.verdict === 'delivered' ? '' : ` · ${h.reason || ''}`}`
    li.append(top, why)
    return li
  }))
}

$('enabled').addEventListener('change', (e) => chrome.storage.local.set({ enabled: e.target.checked }))
$('open-monitor').addEventListener('click', () => chrome.tabs.create({ url: `${VAJRA}/#/monitor` }))
$('open-samples').addEventListener('click', () => chrome.tabs.create({ url: 'http://127.0.0.1:8090/downloads' }))
$('clear').addEventListener('click', async () => {
  await chrome.storage.local.set({ history: [], counts: { checked: 0, delivered: 0, burned: 0, blocked: 0 } })
  await chrome.action.setBadgeText({ text: '' })
  location.reload()
})

loadStatus()
loadHistory()
