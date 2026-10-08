import { useEffect, useRef, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { Icon } from './Icon.jsx'

// Secure convert: a real third-party tool (iLovePDF) turns images into a PDF, and VAJRA checks
// both the image going in and the PDF coming out before anything reaches the user's device.

const STAGES = [
  { id: 'receive', label: 'Your image', icon: 'image' },
  { id: 'image', label: 'Image check', icon: 'search' },
  { id: 'convert', label: 'PDF tool', icon: 'tool' },
  { id: 'scan', label: 'Sandbox scan', icon: 'shield' },
  { id: 'final', label: 'Your device', icon: 'download' },
]

function fmtBytes(n) {
  return n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`
}

export function ConvertPage() {
  const [status, setStatus] = useState(null)
  const [files, setFiles] = useState([])
  const [engine, setEngine] = useState('ilovepdf')
  const [tamper, setTamper] = useState('none')
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState(null)
  const [shown, setShown] = useState(0)
  const [error, setError] = useState(null)
  const [drag, setDrag] = useState(false)
  const input = useRef(null)

  useEffect(() => {
    fetch('/api/convert/status').then((r) => r.json()).then((s) => {
      setStatus(s)
      if (!s.ilovepdf) setEngine('offline')
    }).catch(() => setStatus({ ilovepdf: false, tamper_tests: { none: 'None' } }))
  }, [])

  // Reveal the pipeline one stage at a time so the order of checks is visible.
  useEffect(() => {
    if (!report) return
    setShown(0)
    const n = report.steps.length
    let i = 0
    const t = setInterval(() => { i += 1; setShown(i); if (i >= n) clearInterval(t) }, 450)
    return () => clearInterval(t)
  }, [report])

  useEffect(() => () => files.forEach((f) => URL.revokeObjectURL(f.url)), [files])

  const pick = (list) => {
    const imgs = [...list].filter((f) => /^image\//.test(f.type) || /\.(jpe?g|png|webp)$/i.test(f.name)).slice(0, 10)
    setFiles(imgs.map((file) => ({ file, url: URL.createObjectURL(file) })))
    setReport(null)
    setError(null)
  }

  const run = async () => {
    setBusy(true)
    setReport(null)
    setError(null)
    const form = new FormData()
    files.forEach(({ file }) => form.append('files', file, file.name))
    form.append('engine', engine)
    form.append('tamper', tamper)
    try {
      const r = await fetch('/api/convert', { method: 'POST', body: form })
      const body = await r.json()
      if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`)
      setReport(body)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const steps = report ? report.steps.slice(0, shown) : []
  const done = report && shown >= report.steps.length
  const byId = Object.fromEntries(steps.map((s) => [s.id, s]))
  const finalStep = byId.deliver || byId.burn || (done && report.verdict !== 'delivered' ? { ok: false } : null)
  const stageState = (id) => {
    if (id === 'final') {
      if (!finalStep) return busy ? 'idle' : 'idle'
      return report.verdict === 'delivered' ? 'ok' : 'bad'
    }
    const s = byId[id]
    if (s) return s.ok ? 'ok' : 'bad'
    if (busy) return 'run'
    return 'idle'
  }
  const engineName = engine === 'ilovepdf' ? 'iLovePDF' : 'Offline converter'

  return (
    <div className="page">
      <PageHeader
        eyebrow="Real tool"
        title="Secure convert"
        lead="Turn a photo into a PDF with iLovePDF, a real online tool. VAJRA checks your image before it leaves, and checks the PDF that comes back before it reaches your device. Anything unsafe is burned in the sandbox."
      />

      <div className="cv-layout">
        <section className="panel cv-input">
          <div
            className={`cv-drop ${drag ? 'drag' : ''}`}
            onClick={() => input.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files) }}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
          >
            <Icon name="upload" size={26} />
            <strong>Choose images</strong>
            <span>JPG, PNG or WEBP, up to 10 images. On a phone you can take a photo.</span>
            <input ref={input} type="file" accept="image/jpeg,image/png,image/webp" multiple hidden onChange={(e) => pick(e.target.files)} />
          </div>

          {files.length > 0 && (
            <ul className="cv-thumbs">
              {files.map(({ file, url }) => (
                <li key={url}>
                  <img src={url} alt="" />
                  <span title={file.name}>{file.name}</span>
                  <small>{fmtBytes(file.size)}</small>
                </li>
              ))}
            </ul>
          )}

          <fieldset className="cv-field">
            <legend>Converter</legend>
            <label className={`cv-option ${engine === 'ilovepdf' ? 'on' : ''} ${status && !status.ilovepdf ? 'off' : ''}`}>
              <input type="radio" name="engine" checked={engine === 'ilovepdf'} disabled={status && !status.ilovepdf} onChange={() => setEngine('ilovepdf')} />
              <span>
                <strong>iLovePDF</strong>
                <small>{status?.ilovepdf ? 'Online, real third-party service' : 'Add ILOVEPDF_PUBLIC_KEY to .env to enable'}</small>
              </span>
            </label>
            <label className={`cv-option ${engine === 'offline' ? 'on' : ''}`}>
              <input type="radio" name="engine" checked={engine === 'offline'} onChange={() => setEngine('offline')} />
              <span>
                <strong>Offline converter</strong>
                <small>Backup when there is no internet</small>
              </span>
            </label>
          </fieldset>

          <details className="cv-test">
            <summary>Demonstration: tamper with the returned file</summary>
            <p>Changes the PDF after the tool returns it, as a compromised service or network could, to show VAJRA burning it.</p>
            <select value={tamper} onChange={(e) => setTamper(e.target.value)}>
              {Object.entries(status?.tamper_tests || { none: 'None' }).map(([id, label]) => (
                <option key={id} value={id}>{label}</option>
              ))}
            </select>
          </details>

          <button className="btn primary cv-go" disabled={!files.length || busy} onClick={run}>
            <Icon name={busy ? 'refresh' : 'shield-check'} size={15} />
            {busy ? `Converting with ${engineName}` : 'Convert securely'}
          </button>
          {error && <p className="cv-error"><Icon name="alert" size={14} /> {error}</p>}
        </section>

        <section className="panel cv-flow">
          <ol className="cv-stages">
            {STAGES.map((s, i) => {
              const st = stageState(s.id)
              const label = s.id === 'convert' ? engineName : s.id === 'final' && report && done && report.verdict !== 'delivered' ? 'Burned' : s.label
              return (
                <li key={s.id} className={`cv-stage ${st}`}>
                  <span className="cv-node">
                    <Icon name={st === 'ok' ? 'check' : st === 'bad' ? (s.id === 'final' ? 'flame' : 'x') : s.id === 'final' && report?.verdict === 'burned' ? 'flame' : s.icon} size={18} />
                  </span>
                  <span className="cv-stage-label">{label}</span>
                  {s.id === 'convert' && <span className="cv-sub">via VAJRA, jailed</span>}
                  {s.id === 'scan' && <span className="cv-sub">in the sandbox</span>}
                  {i < STAGES.length - 1 && <span className="cv-edge" />}
                </li>
              )
            })}
          </ol>

          {!report && !busy && (
            <p className="cv-empty muted">Choose an image and press Convert securely. Each step appears here as VAJRA runs it.</p>
          )}
          {busy && <p className="cv-empty muted">Working: checking your image, converting, then scanning the result.</p>}

          {report && (
            <ul className="cv-log">
              {steps.map((s) => (
                <li key={s.id} className={`${s.ok ? 'ok' : 'bad'} ${s.test ? 'test' : ''}`}>
                  <Icon name={s.id === 'burn' ? 'flame' : s.test ? 'flask' : s.ok ? 'check-circle' : 'x'} size={15} />
                  <div>
                    <strong>{s.title}</strong>
                    <span>{s.detail}</span>
                    {s.isolation && <span className="cv-meta">Tool process: {s.isolation}</span>}
                  </div>
                </li>
              ))}
            </ul>
          )}

          {done && report.verdict === 'delivered' && (
            <div className="cv-verdict ok">
              <Icon name="shield-check" size={22} />
              <div>
                <strong>Safe. Every check passed.</strong>
                <span>{report.filename} is ready. The link works for 30 minutes.</span>
              </div>
              <a className="btn primary" href={report.download} download={report.filename}>
                <Icon name="download" size={15} /> Download PDF
              </a>
            </div>
          )}
          {done && report.verdict === 'burned' && (
            <div className="cv-verdict bad">
              <Icon name="flame" size={22} />
              <div>
                <strong>Burned in the sandbox. Nothing was sent to your device.</strong>
                <span>{report.reason}</span>
              </div>
            </div>
          )}
          {done && (report.verdict === 'error' || report.verdict === 'rejected') && (
            <div className="cv-verdict warn">
              <Icon name="alert" size={22} />
              <div>
                <strong>Not converted.</strong>
                <span>{report.reason}. Nothing was sent to your device.</span>
              </div>
            </div>
          )}

          {done && (report.scan || report.images) && (
            <details className="cv-detail" open={report.verdict === 'burned'}>
              <summary>What the sandbox checked</summary>
              {report.images?.map((im) => (
                <CheckList key={im.fingerprint || im.name} title={`Image: ${im.name}`} rep={im} />
              ))}
              {report.scan && <CheckList title="PDF returned by the tool" rep={report.scan} />}
            </details>
          )}
        </section>
      </div>
    </div>
  )
}

function CheckList({ title, rep }) {
  return (
    <div className="cv-checks">
      <h4>{title} <small>{rep.fingerprint}</small></h4>
      <ul>
        {rep.checks?.map((c) => (
          <li key={c.name} className={c.ok ? 'ok' : 'bad'}>
            <Icon name={c.ok ? 'check' : 'x'} size={13} /> <strong>{c.name}</strong> <span>{c.detail}</span>
          </li>
        ))}
        {rep.removed?.map((r) => (
          <li key={r.kind} className="removed">
            <Icon name="flame" size={13} /> <strong>Removed</strong> <span>{r.kind}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
