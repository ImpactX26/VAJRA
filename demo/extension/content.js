// VAJRA Upload Guard (content script).
//
// When a page receives files (file picker or drag and drop), the event is held before the page's own
// code sees it. PDFs and images are sent to VAJRA's sandbox through the extension's background worker.
// Safe files are handed to the page; unsafe files are burned and never reach the website.
// If VAJRA is offline, guarded files are held back (fail closed).

(() => {
  if (window.__vajraUploadGuard) return
  window.__vajraUploadGuard = true
  if (location.origin === 'http://127.0.0.1:8001') return // VAJRA's own site checks files itself

  const GUARDED = (f) => /^(application\/pdf|image\/(png|jpe?g|webp))$/i.test(f.type) || /\.(pdf|png|jpe?g|webp)$/i.test(f.name)
  const released = new WeakSet() // events VAJRA re-sent after approval: let these through untouched

  function toDataUrl(file) {
    return new Promise((res, rej) => {
      const r = new FileReader()
      r.onload = () => res(r.result)
      r.onerror = () => rej(r.error)
      r.readAsDataURL(file)
    })
  }

  async function check(files) {
    const payload = []
    for (const f of files) {
      payload.push(GUARDED(f) ? { name: f.name, type: f.type, data: await toDataUrl(f) } : { name: f.name, type: f.type, skip: true })
    }
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'vajra-upload-check', host: location.hostname, files: payload })
      return reply?.results || files.map((f) => ({ name: f.name, verdict: 'blocked', reason: 'no answer from VAJRA' }))
    } catch {
      return files.map((f) => ({ name: f.name, verdict: 'blocked', reason: 'extension unavailable' }))
    }
  }

  // ---------------------------------------------------------------- on-page notice
  let host
  function panel() {
    if (host && document.documentElement.contains(host)) return host.shadowRoot.querySelector('.stack')
    host = document.createElement('vajra-guard')
    host.style.cssText = 'all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647;'
    const root = host.attachShadow({ mode: 'open' })
    root.innerHTML = `<style>
      .stack { display: flex; flex-direction: column; gap: 10px; width: 360px; font: 13px/1.45 Inter, 'Segoe UI', system-ui, sans-serif; }
      .card { display: grid; grid-template-columns: 38px 1fr 20px; gap: 12px; padding: 14px; border-radius: 14px; color: #e2e8f0;
        background: #0b1220; border: 1px solid rgba(148,163,184,.25); box-shadow: 0 18px 40px rgba(0,0,0,.35);
        animation: pop .35s cubic-bezier(.2,1.3,.4,1) both; }
      .card.burned { border-color: rgba(248,113,113,.6); }
      .card.ok { border-color: rgba(74,222,128,.5); }
      .card.wait { border-color: rgba(96,165,250,.5); }
      @keyframes pop { from { transform: translateY(-8px) scale(.97); } }
      img { width: 38px; height: 38px; }
      .title { font-weight: 700; color: #fff; font-size: 14px; }
      .brand { font-size: 11px; letter-spacing: .12em; font-weight: 800; color: #93c5fd; text-transform: uppercase; }
      .why { color: #94a3b8; font-size: 12.5px; margin-top: 2px; overflow-wrap: anywhere; }
      .why b { color: #fca5a5; font-weight: 600; }
      button { all: unset; cursor: pointer; color: #64748b; font-size: 18px; line-height: 1; text-align: center; }
      button:hover { color: #e2e8f0; }
      .spin { width: 30px; height: 30px; margin: 4px; border-radius: 50%; border: 3px solid rgba(96,165,250,.25); border-top-color: #60a5fa; animation: s 0.8s linear infinite; }
      @keyframes s { to { transform: rotate(360deg); } }
    </style><div class="stack"></div>`
    document.documentElement.appendChild(host)
    return root.querySelector('.stack')
  }

  function card(kind, title, lines) {
    const el = document.createElement('div')
    el.className = `card ${kind}`
    const icon = kind === 'wait' ? '<div class="spin"></div>'
      : `<img alt="" src="${chrome.runtime.getURL(kind === 'ok' ? 'icons/ok.png' : kind === 'burned' ? 'icons/burn.png' : 'icons/offline.png')}">`
    el.innerHTML = `${icon}<div><div class="brand">VAJRA Upload Guard</div><div class="title"></div><div class="why"></div></div><button aria-label="Close">×</button>`
    el.querySelector('.title').textContent = title
    const why = el.querySelector('.why')
    for (const [name, reason] of lines) {
      const row = document.createElement('div')
      const b = document.createElement('b')
      b.textContent = name
      row.append(b, reason ? `: ${reason}` : '')
      why.append(row)
    }
    el.querySelector('button').onclick = () => el.remove()
    panel().prepend(el)
    if (kind !== 'burned') setTimeout(() => el.remove(), kind === 'wait' ? 60000 : 6000)
    return el
  }

  async function screen(files) {
    const guarded = files.filter(GUARDED)
    if (!guarded.length) return { allowed: files, results: [] }
    const waiting = card('wait', `Checking ${guarded.length} file(s) in the sandbox`, guarded.map((f) => [f.name, 'before upload']))
    const results = await check(files)
    waiting.remove()
    const bad = results.filter((r) => r.verdict === 'burned' || r.verdict === 'blocked')
    const okNames = new Set(results.filter((r) => !bad.includes(r)).map((r) => r.name))
    if (bad.some((r) => r.verdict === 'burned')) {
      card('burned', 'Burned before upload. This website never received it.',
        bad.map((r) => [r.name, r.reason]))
    } else if (bad.length) {
      card('offline', 'Upload held back', bad.map((r) => [r.name, r.reason]))
    }
    if (okNames.size && guarded.some((f) => okNames.has(f.name))) {
      card('ok', 'Checked by VAJRA: safe to upload', guarded.filter((f) => okNames.has(f.name)).map((f) => [f.name, '']))
    }
    return { allowed: files.filter((f) => okNames.has(f.name) || !GUARDED(f)), results }
  }

  // ---------------------------------------------------------------- file picker
  const pendingInputs = new WeakSet()
  function onPick(e) {
    const input = e.target
    if (!(input instanceof HTMLInputElement) || input.type !== 'file' || released.has(e)) return
    if (!input.files || !input.files.length || ![...input.files].some(GUARDED)) return
    e.stopImmediatePropagation()
    if (e.type !== 'change' || pendingInputs.has(input)) return
    pendingInputs.add(input)
    const files = [...input.files]
    screen(files).then(({ allowed }) => {
      pendingInputs.delete(input)
      const dt = new DataTransfer()
      allowed.forEach((f) => dt.items.add(f))
      input.files = dt.files
      if (!allowed.length) { input.value = ''; return }
      for (const type of ['input', 'change']) {
        const ev = new Event(type, { bubbles: true })
        released.add(ev)
        input.dispatchEvent(ev)
      }
    })
  }
  window.addEventListener('input', onPick, true)
  window.addEventListener('change', onPick, true)

  // ---------------------------------------------------------------- drag and drop
  window.addEventListener('drop', (e) => {
    if (released.has(e) || !e.dataTransfer || ![...e.dataTransfer.files].some(GUARDED)) return
    e.preventDefault()
    e.stopImmediatePropagation()
    const target = e.target
    const files = [...e.dataTransfer.files]
    const at = { clientX: e.clientX, clientY: e.clientY, screenX: e.screenX, screenY: e.screenY }
    screen(files).then(({ allowed }) => {
      if (!allowed.length) return
      const dt = new DataTransfer()
      allowed.forEach((f) => dt.items.add(f))
      const ev = new DragEvent('drop', { bubbles: true, cancelable: true, composed: true, dataTransfer: dt, ...at })
      released.add(ev)
      target.dispatchEvent(ev)
    })
  }, true)
})()
