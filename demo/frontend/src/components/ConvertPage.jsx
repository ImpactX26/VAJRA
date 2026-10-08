import { useEffect, useRef, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { Icon } from './Icon.jsx'

// Secure convert: a real third-party tool (iLovePDF) turns images into a PDF or merges PDFs, and
// VAJRA checks both the files going in and the PDF coming out before anything reaches the user's device.

const OPS = {
  imagepdf: {
    label: 'Image to PDF', min: 1, input: 'Your image', check: 'Image check', verb: 'Converting',
    accept: 'image/jpeg,image/png,image/webp', pick: 'Choose images',
    hint: 'JPG, PNG or WEBP, up to 10 images. On a phone you can take a photo.',
    ok: (f) => /^image\//.test(f.type) || /\.(jpe?g|png|webp)$/i.test(f.name),
  },
  merge: {
    label: 'Merge PDFs', min: 2, input: 'Your PDFs', check: 'PDF check', verb: 'Merging',
    accept: 'application/pdf,.pdf', pick: 'Choose PDFs',
    hint: 'Two to ten PDF files. They are merged in the order shown.',
    ok: (f) => f.type === 'application/pdf' || /\.pdf$/i.test(f.name),
  },
}

const STAGES = [
  { id: 'receive', icon: 'image' },
  { id: 'image', icon: 'search' },
  { id: 'convert', label: 'PDF tool', icon: 'tool' },
  { id: 'scan', label: 'Sandbox scan', icon: 'shield' },
  { id: 'final', label: 'Your device', icon: 'download' },
]

function fmtBytes(n) {
  return n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`
}

export function ConvertPage({ initial }) {
  const [status, setStatus] = useState(null)
  const [op, setOp] = useState(initial === 'merge' ? 'merge' : 'imagepdf')
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
    const chosen = [...list].filter(OPS[op].ok).slice(0, 10)
    setFiles(chosen.map((file) => ({ file, url: URL.createObjectURL(file) })))
    setReport(null)
    setError(null)
  }

  const switchOp = (next) => {
    if (next === op) return
    setOp(next)
    setFiles([])
    setReport(null)
    setError(null)
  }

  const move = (i, d) => setFiles((fs) => {
    const j = i + d
    if (j < 0 || j >= fs.length) return fs
    const out = [...fs]
    ;[out[i], out[j]] = [out[j], out[i]]
    return out
  })

  const run = async () => {
    setBusy(true)
    setReport(null)
    setError(null)
    const form = new FormData()
    files.forEach(({ file }) => form.append('files', file, file.name))
    form.append('engine', engine)
    form.append('operation', op)
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
  const o = OPS[op]
  const ready = files.length >= o.min

  return (
    <div className="page">
      <PageHeader
        eyebrow="Real tool"
        title="Secure convert"
        lead="Turn photos into a PDF or merge PDFs with iLovePDF, a real online tool. VAJRA checks your files before they leave, and checks the PDF that comes back before it reaches your device. Anything unsafe is burned in the sandbox."
      />

      <div className="cv-layout">
        <section className="panel cv-input">
          <div className="cv-ops" role="tablist" aria-label="PDF task">
            {Object.entries(OPS).map(([id, def]) => (
              <button key={id} role="tab" aria-selected={op === id} className={op === id ? 'on' : ''} onClick={() => switchOp(id)} disabled={busy}>
                <Icon name={id === 'merge' ? 'layers' : 'image'} size={14} /> {def.label}
              </button>
            ))}
          </div>
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
            <strong>{o.pick}</strong>
            <span>{o.hint}</span>
            <input key={op} ref={input} type="file" accept={o.accept} multiple hidden onChange={(e) => pick(e.target.files)} />
          </div>

          {op === 'merge' && files.length > 0 && (
            <ol className="cv-files">
              {files.map(({ file, url }, i) => (
                <li key={url}>
                  <span className="cv-order">{i + 1}</span>
                  <Icon name="file" size={16} />
                  <span className="cv-fname" title={file.name}>{file.name}</span>
                  <small>{fmtBytes(file.size)}</small>
                  <button className="cv-mv" onClick={() => move(i, -1)} disabled={i === 0 || busy} aria-label={`Move ${file.name} up`}>
                    <Icon name="chevron-down" size={14} style={{ transform: 'rotate(180deg)' }} />
                  </button>
                  <button className="cv-mv" onClick={() => move(i, 1)} disabled={i === files.length - 1 || busy} aria-label={`Move ${file.name} down`}>
                    <Icon name="chevron-down" size={14} />
                  </button>
                </li>
              ))}
            </ol>
          )}
          {op === 'merge' && files.length === 1 && <p className="cv-hint muted">Add at least one more PDF to merge.</p>}

          {op === 'imagepdf' && files.length > 0 && (
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

          <button className="btn primary cv-go" disabled={!ready || busy} onClick={run}>
            <Icon name={busy ? 'refresh' : 'shield-check'} size={15} />
            {busy ? `${o.verb} with ${engineName}` : op === 'merge' ? 'Merge securely' : 'Convert securely'}
          </button>
          {error && <p className="cv-error"><Icon name="alert" size={14} /> {error}</p>}
        </section>

        <section className="panel cv-flow">
          <ol className="cv-stages">
            {STAGES.map((s, i) => {
              const st = stageState(s.id)
              const label = s.id === 'receive' ? o.input : s.id === 'image' ? o.check : s.id === 'convert' ? engineName
                : s.id === 'final' && report && done && report.verdict !== 'delivered' ? 'Burned' : s.label
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
            <p className="cv-empty muted">{op === 'merge' ? 'Choose two or more PDFs and press Merge securely.' : 'Choose an image and press Convert securely.'} Each step appears here as VAJRA runs it.</p>
          )}
          {busy && <p className="cv-empty muted">Working: checking your files, running {engineName}, then scanning the result.</p>}

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

          {done && (report.scan || report.images || report.inputs) && (
            <details className="cv-detail" open={report.verdict === 'burned'}>
              <summary>What the sandbox checked</summary>
              {report.images?.map((im) => (
                <CheckList key={im.fingerprint || im.name} title={`Image: ${im.name}`} rep={im} />
              ))}
              {report.inputs?.map((im, i) => (
                <CheckList key={`${i}-${im.fingerprint}`} title={`Your PDF: ${im.name}`} rep={im} />
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
        {rep.notes?.map((n) => (
          <li key={n} className="note">
            <Icon name="info" size={13} /> <strong>Noted</strong> <span>{n} (allowed in documents; runs nothing)</span>
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
