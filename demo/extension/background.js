// VAJRA Download Guard (service worker).
//
// Every PDF or image download is stopped before it reaches the disk, fetched by the extension,
// and sent to the local VAJRA server, which checks it inside its OS sandbox. A safe file is then
// downloaded from VAJRA (images rebuilt without metadata); an unsafe file is burned and never saved.
// If VAJRA is not running, guarded downloads are blocked (fail closed), never waved through.

export const VAJRA = 'http://127.0.0.1:8001'
const GUARDED_MIME = /^(application\/pdf|image\/(png|jpe?g|webp))\b/i
const GUARDED_EXT = /\.(pdf|png|jpe?g|webp)(?:$|[?#])/i
const HISTORY_MAX = 25

// ------------------------------------------------------------------ settings and history
async function settings() {
  const { enabled = true } = await chrome.storage.local.get('enabled')
  return { enabled }
}

async function remember(entry) {
  const { history = [], counts = { checked: 0, delivered: 0, burned: 0, blocked: 0 } } =
    await chrome.storage.local.get(['history', 'counts'])
  history.unshift({ time: Date.now(), ...entry })
  counts.checked += 1
  if (entry.verdict in counts) counts[entry.verdict] += 1
  await chrome.storage.local.set({ history: history.slice(0, HISTORY_MAX), counts })
  const stopped = counts.burned + counts.blocked
  await chrome.action.setBadgeText({ text: stopped ? String(stopped) : '' })
  await chrome.action.setBadgeBackgroundColor({ color: '#dc2626' })
}

function notify(kind, title, message) {
  const icon = { ok: 'icons/ok.png', burn: 'icons/burn.png', offline: 'icons/offline.png', info: 'icons/icon128.png' }[kind]
  chrome.notifications.create({ type: 'basic', iconUrl: icon, title, message: message.slice(0, 250), priority: 2 })
}

// ------------------------------------------------------------------ the check itself
function nameFrom(url, disposition) {
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition || '')
  if (m) return decodeURIComponent(m[1])
  try {
    const last = new URL(url).pathname.split('/').filter(Boolean).pop()
    return last ? decodeURIComponent(last) : 'download'
  } catch {
    return 'download'
  }
}

async function vajraOnline() {
  try {
    return (await fetch(`${VAJRA}/api/status`, { cache: 'no-store' })).ok
  } catch {
    return false
  }
}

export async function checkUrl(url, hintName) {
  const host = (() => { try { return new URL(url).hostname } catch { return 'unknown' } })()
  if (!(await vajraOnline())) {
    notify('offline', 'Download blocked: VAJRA is offline', `${hintName || host}: start the VAJRA server, then try again.`)
    await remember({ name: hintName || url, source: host, verdict: 'blocked', reason: 'VAJRA server offline' })
    return
  }

  let blob, name
  try {
    ({ blob, name } = await fetchBytes(url, hintName))
  } catch (e) {
    notify('offline', 'Download blocked', `Could not fetch the file for checking (${e.message}).`)
    await remember({ name: hintName || url, source: host, verdict: 'blocked', reason: `fetch failed: ${e.message}` })
    return
  }

  const form = new FormData()
  form.append('file', blob, name)
  form.append('url', url)
  let report
  try {
    report = await (await fetch(`${VAJRA}/api/guard/check`, { method: 'POST', body: form })).json()
  } catch (e) {
    notify('offline', 'Download blocked', `VAJRA could not check ${name}.`)
    await remember({ name, source: host, verdict: 'blocked', reason: 'check failed' })
    return
  }

  if (report.verdict === 'delivered') {
    await chrome.downloads.download({ url: `${VAJRA}${report.download}`, filename: report.filename, conflictAction: 'uniquify' })
    const cleaned = (report.removed || []).length ? ' Hidden metadata was removed.' : ''
    notify('ok', 'Safe: checked by VAJRA', `${report.filename} passed every sandbox check.${cleaned}`)
  } else if (report.verdict === 'burned') {
    notify('burn', 'Burned by VAJRA', `${name} was not saved. ${report.reason}`)
  } else {
    // Not a PDF or image after all: VAJRA does not inspect it, so hand it back unchanged.
    await chrome.downloads.download({ url, filename: name, conflictAction: 'uniquify' })
  }
  await remember({ name: report.filename || name, source: host, verdict: report.verdict, reason: report.reason })
}

// ------------------------------------------------------------------ getting the bytes again
// Ordinary links are fetched again by the extension. Files a page generated itself (blob: URLs)
// only exist inside that page, so they are read from the tab that created them.
async function fetchBytes(url, hintName) {
  if (url.startsWith('blob:')) {
    const origin = new URL(url.slice(5)).origin
    const tabs = await chrome.tabs.query({ url: `${origin}/*` })
    for (const tab of tabs) {
      try {
        const [{ result }] = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          args: [url],
          func: async (u) => {
            const b = await (await fetch(u)).blob()
            const data = await new Promise((res) => { const r = new FileReader(); r.onload = () => res(r.result); r.readAsDataURL(b) })
            return { type: b.type, data }
          },
        })
        if (result && result.data) {
          const bytes = Uint8Array.from(atob(result.data.split(',')[1] || ''), (c) => c.charCodeAt(0))
          return { blob: new Blob([bytes], { type: result.type }), name: hintName || 'download' }
        }
      } catch {}
    }
    throw new Error('the page no longer holds this file')
  }
  const resp = await fetch(url, { credentials: 'include' })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return { blob: await resp.blob(), name: hintName || nameFrom(url, resp.headers.get('content-disposition')) }
}

// ------------------------------------------------------------------ intercept downloads
// Decided when Chrome knows the real file name (from Content-Disposition) but before the file is
// moved into place. Many sites serve files from links without an extension (ilovepdf.com does),
// so a decision at download creation, when only the URL is known, would miss them.
async function stop(id) {
  try { await chrome.downloads.cancel(id) } catch {}
  const [now] = await chrome.downloads.search({ id })
  if (now && now.state === 'complete' && now.exists) {
    try { await chrome.downloads.removeFile(id) } catch {}
  }
  try { await chrome.downloads.erase({ id }) } catch {}
}

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  const url = item.finalUrl || item.url
  const name = (item.filename || '').split(/[\\/]/).pop()
  const guarded = item.byExtensionId !== chrome.runtime.id && !url.startsWith(VAJRA) &&
    (GUARDED_MIME.test(item.mime || '') || GUARDED_EXT.test(name) || GUARDED_EXT.test(url))
  if (!guarded) return void suggest()
  settings().then(async ({ enabled }) => {
    if (!enabled) return void suggest()
    await stop(item.id)
    try { suggest() } catch {}
    await checkUrl(url, name || undefined)
  })
  return true // answered asynchronously
})

// ------------------------------------------------------------------ right-click menu
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'vajra-check-link', title: 'Check this file with VAJRA', contexts: ['link'] })
    chrome.contextMenus.create({ id: 'vajra-check-image', title: 'Save this image through VAJRA', contexts: ['image'] })
    chrome.contextMenus.create({ id: 'vajra-image-pdf', title: 'Convert this image to PDF with VAJRA (iLovePDF)', contexts: ['image'] })
  })
  chrome.action.setBadgeText({ text: '' })
})

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === 'vajra-check-link') return checkUrl(info.linkUrl)
  if (info.menuItemId === 'vajra-check-image') return checkUrl(info.srcUrl)
  if (info.menuItemId === 'vajra-image-pdf') return imageToPdf(info.srcUrl)
})

async function imageToPdf(url) {
  const host = (() => { try { return new URL(url).hostname } catch { return 'unknown' } })()
  if (!(await vajraOnline())) {
    notify('offline', 'VAJRA is offline', 'Start the VAJRA server, then try again.')
    return
  }
  notify('info', 'Converting with iLovePDF', 'VAJRA is checking the image, converting it and scanning the PDF.')
  try {
    const blob = await (await fetch(url, { credentials: 'include' })).blob()
    const status = await (await fetch(`${VAJRA}/api/convert/status`)).json()
    const form = new FormData()
    form.append('files', blob, nameFrom(url))
    form.append('operation', 'imagepdf')
    form.append('engine', status.ilovepdf ? 'ilovepdf' : 'offline')
    form.append('tamper', 'none')
    const report = await (await fetch(`${VAJRA}/api/convert`, { method: 'POST', body: form })).json()
    if (report.verdict === 'delivered') {
      await chrome.downloads.download({ url: `${VAJRA}${report.download}`, filename: report.filename, conflictAction: 'uniquify' })
      notify('ok', 'PDF ready: checked by VAJRA', `${report.filename} passed every sandbox check.`)
    } else {
      notify('burn', report.verdict === 'burned' ? 'Burned by VAJRA' : 'Not converted', report.reason || 'see the VAJRA Monitor page')
    }
    await remember({ name: report.filename || nameFrom(url), source: host, verdict: report.verdict, reason: report.reason })
  } catch (e) {
    notify('offline', 'Conversion failed', e.message)
  }
}

// ------------------------------------------------------------------ upload guard (from content.js)
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.type !== 'vajra-upload-check') return
  checkUploads(msg).then((results) => reply({ results }))
  return true // reply asynchronously
})

async function checkUploads({ host, files }) {
  if (!(await settings()).enabled) return files.map((f) => ({ name: f.name, verdict: 'skipped' }))
  const online = await vajraOnline()
  const results = []
  for (const f of files) {
    if (f.skip) { results.push({ name: f.name, verdict: 'skipped' }); continue }
    if (!online) {
      results.push({ name: f.name, verdict: 'blocked', reason: 'VAJRA server offline' })
      await remember({ name: f.name, source: host, dir: 'upload', verdict: 'blocked', reason: 'VAJRA server offline' })
      continue
    }
    try {
      const bytes = Uint8Array.from(atob(f.data.split(',')[1] || ''), (c) => c.charCodeAt(0))
      const form = new FormData()
      form.append('file', new Blob([bytes], { type: f.type }), f.name)
      form.append('url', `https://${host}/`)
      form.append('direction', 'upload')
      const report = await (await fetch(`${VAJRA}/api/guard/check`, { method: 'POST', body: form })).json()
      const verdict = report.verdict === 'skipped' ? 'skipped' : report.verdict
      results.push({ name: f.name, verdict, reason: report.reason })
      if (verdict !== 'skipped') await remember({ name: f.name, source: host, dir: 'upload', verdict, reason: report.reason })
      if (verdict === 'burned') notify('burn', 'Burned before upload', `${f.name} was not sent to ${host}. ${report.reason}`)
    } catch (e) {
      results.push({ name: f.name, verdict: 'blocked', reason: 'check failed' })
      await remember({ name: f.name, source: host, dir: 'upload', verdict: 'blocked', reason: 'check failed' })
    }
  }
  return results
}
