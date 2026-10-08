import { useEffect, useRef, useState } from 'react'

// Animated tool import: every tool enters VAJRA's sandbox, its four checks run,
// and it is either burned or delivered to the assistant.

const CHECKS = [
  { id: 'pin', label: 'Same as reviewed version', fails: (r) => r.includes('pin mismatch') },
  { id: 'name', label: 'Unique, valid name', fails: (r) => r.includes('shadowing') || r.includes('invalid tool name') },
  { id: 'hidden', label: 'No hidden characters', fails: (r) => r.includes('hidden characters') },
  { id: 'shape', label: 'Well-formed definition', fails: (r) => r.includes('longer than') || r.includes('schema') },
]
const STEP_MS = 1100

export function SandboxPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(0) // tools fully processed
  const timer = useRef(null)

  useEffect(() => () => clearInterval(timer.current), [])
  // ?autoimport=1 starts the import on load (hands-free demo / screen recording).
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('autoimport')) importTools()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

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

  const tools = data?.tools || []
  const current = tools[done] // the one inside the sandbox right now
  const processed = tools.slice(0, done)
  const delivered = processed.filter((t) => t.admitted)
  const burned = processed.filter((t) => !t.admitted)

  return (
    <div className="page">
      <h1 className="page-title">Sandbox</h1>
      <p className="lead">
        Every tool imported from an MCP server enters VAJRA’s sandbox first. Unsafe tools are burned there; the assistant
        only receives the safe ones.
      </p>
      <div>
        <button className="btn primary big" onClick={importTools} disabled={loading}>
          {loading ? 'Connecting to servers…' : data ? '↻ Import again' : '📥 Import tools from MCP servers'}
        </button>
      </div>

      <section className="sbx">
        <div className="sbx-col">
          <h3>📦 Incoming tools</h3>
          {!data && <p className="muted">Nothing imported yet.</p>}
          <ul className="sbx-list">
            {tools.map((t, i) => (
              <li key={`${t.server}/${t.tool}`} className={`sbx-chip ${i < done ? 'gone' : i === done ? 'active' : ''}`}>
                <span className="muted">{t.server}/</span>{t.tool}
              </li>
            ))}
          </ul>
        </div>

        <div className={`sbx-box ${current ? 'busy' : ''}`}>
          <div className="sbx-title">🛡️ VAJRA sandbox</div>
          {current ? (
            <div key={done} className="sbx-current">
              <div className="sbx-tool">{current.server}/<b>{current.tool}</b></div>
              <ul className="sbx-checks">
                {CHECKS.map((c, i) => {
                  const failed = !current.admitted && c.fails(current.reason)
                  return (
                    <li key={c.id} className={failed ? 'fail' : 'pass'} style={{ animationDelay: `${i * 0.18}s` }}>
                      {failed ? '✗' : '✓'} {c.label}
                    </li>
                  )
                })}
              </ul>
              <div className={`sbx-verdict ${current.admitted ? 'ok' : 'burn'}`}>
                {current.admitted ? '✅ Safe: delivering' : '🔥 Burning'}
              </div>
            </div>
          ) : (
            <p className="muted sbx-idle">{data ? 'All tools checked.' : 'Waiting for tools…'}</p>
          )}
        </div>

        <div className="sbx-col">
          <h3>✅ Delivered to the assistant <span className="count">{delivered.length}</span></h3>
          <ul className="sbx-list">
            {delivered.map((t) => (
              <li key={`${t.server}/${t.tool}`} className="sbx-chip ok"><span className="muted">{t.server}/</span>{t.tool}</li>
            ))}
          </ul>
          <h3>🔥 Burned in the sandbox <span className="count bad">{burned.length}</span></h3>
          <ul className="sbx-list">
            {burned.map((t) => (
              <li key={`${t.server}/${t.tool}`} className="sbx-chip burn">
                <div><span className="muted">{t.server}/</span>{t.tool}</div>
                <small>{t.reason}</small>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  )
}
