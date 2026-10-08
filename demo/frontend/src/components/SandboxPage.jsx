import { useEffect, useRef, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { Icon } from './Icon.jsx'
import { WinSandboxPanel } from './WinSandboxPanel.jsx'

// Animated tool import: every tool enters VAJRA's sandbox, its four checks run,
// and it is either rejected or delivered to the assistant.

const CHECKS = [
  { id: 'pin', label: 'Matches reviewed version', fails: (r) => r.includes('pin mismatch') },
  { id: 'name', label: 'Unique, valid name', fails: (r) => r.includes('shadowing') || r.includes('invalid tool name') },
  { id: 'hidden', label: 'No hidden characters', fails: (r) => r.includes('hidden characters') },
  { id: 'shape', label: 'Well-formed definition', fails: (r) => r.includes('longer than') || r.includes('schema') },
]
const STEP_MS = 1100

export function SandboxPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(0)
  const [proof, setProof] = useState(null)
  const [proving, setProving] = useState(false)
  const timer = useRef(null)

  const importTools = async () => {
    clearInterval(timer.current)
    setLoading(true)
    setData(null)
    setDone(0)
    try {
      const res = await (await fetch('/api/sandbox')).json()
      setData(res)
      let n = 0
      timer.current = setInterval(() => {
        n += 1
        setDone(n)
        if (n >= res.tools.length) clearInterval(timer.current)
      }, STEP_MS)
    } finally {
      setLoading(false)
    }
  }
  const runProof = async () => {
    setProving(true)
    try {
      setProof(await (await fetch('/api/isolation')).json())
    } finally {
      setProving(false)
    }
  }

  useEffect(() => () => clearInterval(timer.current), [])
  // ?autoimport=1 starts the import and the escape test on load (hands-free demo / recording).
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('autoimport')) {
      importTools()
      runProof()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const tools = data?.tools || []
  const current = tools[done]
  const processed = tools.slice(0, done)
  const delivered = processed.filter((t) => t.admitted)
  const rejected = processed.filter((t) => !t.admitted)
  const pct = tools.length ? Math.round((done / tools.length) * 100) : 0

  return (
    <div className="page">
      <PageHeader
        eyebrow="Isolation"
        title="Sandbox"
        lead="Every tool imported from an MCP server is checked in VAJRA's sandbox first. Unsafe tools are removed there; the assistant only receives the safe ones."
      >
        <div className="cta">
          <button className="btn primary lg" onClick={importTools} disabled={loading}>
            <Icon name={data ? 'refresh' : 'package'} size={15} />
            {loading ? 'Connecting to servers' : data ? 'Import again' : 'Import tools from MCP servers'}
          </button>
        </div>
      </PageHeader>

      {data?.isolation && (
        <div className="iso-strip">
          {Object.entries(data.isolation).map(([s, d]) => (
            <span key={s} className="iso-chip"><Icon name="lock" size={12} /><b>{s}</b><span>{d}</span></span>
          ))}
        </div>
      )}

      {data && (
        <div className="progress" aria-label="Import progress">
          <div className="progress-bar" style={{ width: `${pct}%` }} />
          <span className="progress-label">{done} of {tools.length} tools checked</span>
        </div>
      )}

      <section className="sbx">
        <div className="sbx-col">
          <h3><Icon name="package" size={15} /> Incoming tools</h3>
          {!data && <p className="muted small-text">Nothing imported yet.</p>}
          <ul className="sbx-list">
            {tools.map((t, i) => (
              <li key={`${t.server}/${t.tool}`} className={`sbx-chip ${i < done ? 'gone' : i === done ? 'active' : ''}`}>
                <span className="muted">{t.server}/</span>{t.tool}
              </li>
            ))}
          </ul>
        </div>

        <div className={`sbx-box ${current ? 'busy' : ''}`}>
          <div className="sbx-title"><Icon name="shield" size={15} /> VAJRA sandbox</div>
          {current ? (
            <div key={done} className="sbx-current">
              <div className="sbx-tool">{current.server}/<b>{current.tool}</b></div>
              <ul className="sbx-checks">
                {CHECKS.map((c, i) => {
                  const failed = !current.admitted && c.fails(current.reason)
                  return (
                    <li key={c.id} className={failed ? 'fail' : 'pass'} style={{ animationDelay: `${i * 0.18}s` }}>
                      <Icon name={failed ? 'x' : 'check'} size={14} /> {c.label}
                    </li>
                  )
                })}
              </ul>
              <div className={`sbx-verdict ${current.admitted ? 'ok' : 'burn'}`}>
                <Icon name={current.admitted ? 'check-circle' : 'flame'} size={15} />
                {current.admitted ? 'Admitted' : 'Rejected'}
              </div>
            </div>
          ) : (
            <p className="muted sbx-idle">{data ? 'All tools checked.' : 'Waiting for tools.'}</p>
          )}
        </div>

        <div className="sbx-col">
          <h3><Icon name="check-circle" size={15} /> Delivered to the assistant <span className="count">{delivered.length}</span></h3>
          <ul className="sbx-list">
            {delivered.map((t) => (
              <li key={`${t.server}/${t.tool}`} className="sbx-chip ok"><span className="muted">{t.server}/</span>{t.tool}</li>
            ))}
          </ul>
          <h3><Icon name="flame" size={15} /> Rejected in the sandbox <span className="count bad">{rejected.length}</span></h3>
          <ul className="sbx-list">
            {rejected.map((t) => (
              <li key={`${t.server}/${t.tool}`} className="sbx-chip burn">
                <div><span className="muted">{t.server}/</span>{t.tool}</div>
                <small>{t.reason}</small>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <WinSandboxPanel />

      <section className="box proof">
        <div className="section-head">
          <div>
            <h2 className="section-title">Operating-system isolation test</h2>
            <p className="muted">
              A deliberately misbehaving MCP server tries to start another program and allocate 512 MB of memory, once
              without VAJRA's sandbox and once inside it.
            </p>
          </div>
          <button className="btn primary" onClick={runProof} disabled={proving}>
            <Icon name={proving ? 'activity' : 'play'} size={14} /> {proving ? 'Running' : 'Run the escape test'}
          </button>
        </div>
        {proof && (
          <table className="data-table proof-table">
            <thead>
              <tr><th>Environment</th><th>Start another program</th><th>Allocate 512 MB</th></tr>
            </thead>
            <tbody>
              {proof.map((r) => (
                <tr key={r.isolation}>
                  <td><b>{r.sandbox ? 'Inside VAJRA sandbox' : 'No sandbox'}</b><div className="muted small-text">{r.isolation}</div></td>
                  {[r.start_program, r.grab_memory].map((v, i) => {
                    const blocked = v.startsWith('blocked')
                    return (
                      <td key={i}>
                        <span className={`pill ${blocked ? 'pill-ok' : 'pill-bad'}`}>
                          <Icon name={blocked ? 'ban' : 'alert'} size={12} /> {v}
                        </span>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
