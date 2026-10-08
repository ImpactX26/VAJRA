import { useEffect, useMemo, useRef, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { Icon } from './Icon.jsx'

// Continuous monitoring: live audit trail (SSE), alert feed, integrity scanner and
// hash-chain verification.

const KIND = {
  'run.start': { label: 'Run started', tone: 'muted', group: 'runs' },
  'run.end': { label: 'Run finished', tone: 'muted', group: 'runs' },
  call: { label: 'Tool call', tone: 'info', group: 'calls' },
  block: { label: 'Blocked', tone: 'bad', group: 'blocks' },
  withhold: { label: 'Sealed', tone: 'violet', group: 'withheld' },
  sanitize: { label: 'Content removed', tone: 'warn', group: 'removed' },
  deliver: { label: 'Delivered', tone: 'ok', group: 'runs' },
  isolate: { label: 'Isolated', tone: 'muted', group: 'tools' },
  'tool.admit': { label: 'Tool admitted', tone: 'ok', group: 'tools' },
  'tool.reject': { label: 'Tool rejected', tone: 'bad', group: 'tools' },
  taint_context: { label: 'Context tainted', tone: 'bad', group: 'blocks' },
  alert: { label: 'Alert', tone: 'bad', group: 'alerts' },
  'monitor.scan': { label: 'Integrity scan', tone: 'info', group: 'monitor' },
  'monitor.drift': { label: 'Drift', tone: 'bad', group: 'monitor' },
  'monitor.vm': { label: 'VM state', tone: 'muted', group: 'monitor' },
  'monitor.error': { label: 'Monitor error', tone: 'warn', group: 'monitor' },
  selftest: { label: 'Self-test', tone: 'info', group: 'monitor' },
  context_secret: { label: 'Secret read', tone: 'violet', group: 'withheld' },
}
const FILTERS = [
  ['all', 'All'], ['calls', 'Calls'], ['blocks', 'Blocks'], ['withheld', 'Sealed'], ['removed', 'Removed'],
  ['tools', 'Tools'], ['alerts', 'Alerts'], ['monitor', 'Monitor'], ['runs', 'Runs'],
]
const SEV = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info' }

function subject(r) {
  if (r.kind === 'alert') return r.title
  return r.tool || r.server || r.scenario || (r.session ? `session ${r.session}` : '')
}

function details(r) {
  switch (r.kind) {
    case 'call': return r.arg_labels ? Object.entries(r.arg_labels).map(([k, v]) => `${k}: ${v}`).join(', ') || 'no arguments' : ''
    case 'block': return r.reason
    case 'selftest': return `${r.passed} of ${r.total} threat checks passed`
    case 'withhold': return `${r.chars} chars sealed as ${r.handle?.slice(0, 10)}…`
    case 'sanitize': return `${(r.removed || []).length} hidden part(s) removed; ${r.kept_chars} chars kept`
    case 'tool.admit': return r.fingerprint
    case 'tool.reject': return r.reason
    case 'isolate': return r.isolation
    case 'alert': return r.detail || r.severity
    case 'monitor.scan': return `${r.tools} tools, ${r.rejected} rejected, ${r.drift} drift (${r.reason}, ${r.duration_s}s)`
    case 'monitor.drift': return r.change
    case 'monitor.vm': return r.ready ? `VM ready ${r.url || ''}` : 'VM off'
    case 'run.start': return `provider: ${r.provider}`
    case 'run.end': return `${r.status}; ${r.emails} email(s), ${r.external_recipients} external`
    case 'deliver': return `${r.chars} chars delivered to the user`
    default: return r.error || ''
  }
}

const time = (ts) => (ts ? new Date(ts).toLocaleTimeString() : '')
const ago = (t) => {
  if (!t) return 'never'
  const s = Math.max(0, Math.round(Date.now() / 1000 - t))
  return s < 60 ? `${s}s ago` : `${Math.round(s / 60)} min ago`
}

export function MonitorPage() {
  const [records, setRecords] = useState([])
  const [stats, setStats] = useState(null)
  const [chain, setChain] = useState(null)
  const [scan, setScan] = useState(null)
  const [live, setLive] = useState(false)
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [scanning, setScanning] = useState(false)
  const [, tick] = useState(0)
  const fresh = useRef(new Set())

  const loadStats = () => fetch('/api/audit/stats').then((r) => r.json()).then(setStats).catch(() => {})
  const verify = () => fetch('/api/audit/verify').then((r) => r.json()).then(setChain).catch(() => {})
  const loadScan = () => fetch('/api/monitor/status').then((r) => r.json()).then(setScan).catch(() => {})
  const config = (body) =>
    fetch('/api/monitor/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then((r) => r.json()).then(setScan)
  const scanNow = async () => {
    setScanning(true)
    try {
      await fetch('/api/monitor/scan', { method: 'POST' })
    } finally {
      setScanning(false)
      loadScan()
      loadStats()
    }
  }

  useEffect(() => {
    fetch('/api/audit?limit=400').then((r) => r.json()).then((d) => setRecords(d.records.reverse())).catch(() => {})
    loadStats()
    verify()
    loadScan()
    // ?nolive=1 skips the live stream (static screenshots); the page still polls every 5 s.
    const es = new URLSearchParams(window.location.search).has('nolive') ? { close() {} } : new EventSource('/api/audit/stream')
    es.onopen = () => setLive(true)
    es.onerror = () => setLive(false)
    es.onmessage = (m) => {
      const rec = JSON.parse(m.data)
      fresh.current.add(rec.seq)
      setTimeout(() => fresh.current.delete(rec.seq), 2500)
      setRecords((prev) => [rec, ...prev].slice(0, 600))
    }
    const t1 = setInterval(() => { loadStats(); loadScan() }, 5000)
    const t2 = setInterval(verify, 15000)
    const t3 = setInterval(() => tick((x) => x + 1), 1000)
    return () => { es.close(); clearInterval(t1); clearInterval(t2); clearInterval(t3) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const k = stats?.kinds || {}
  const alerts = records.filter((r) => r.kind === 'alert')
  const critical = alerts.filter((r) => r.severity === 'critical').length
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return records.filter((r) => (filter === 'all' || KIND[r.kind]?.group === filter) && (!q || JSON.stringify(r).toLowerCase().includes(q)))
  }, [records, filter, query])

  const kpis = [
    { label: 'Protected runs', value: k['run.start'] || 0, icon: 'activity' },
    { label: 'Tool calls checked', value: k.call || 0, icon: 'tool' },
    { label: 'Actions blocked', value: k.block || 0, icon: 'ban', tone: 'bad' },
    { label: 'Outputs sealed', value: k.withhold || 0, icon: 'lock', tone: 'violet' },
    { label: 'Hidden content removed', value: k.sanitize || 0, icon: 'flame', tone: 'warn' },
    { label: 'Tools rejected', value: k['tool.reject'] || 0, icon: 'package', tone: 'bad' },
  ]

  return (
    <div className="page">
      <PageHeader eyebrow="Operations" title="Monitor" lead="Continuous monitoring of every VAJRA decision, backed by a tamper-evident audit trail.">
        <div className="mon-actions">
          <span className={`live-pill ${live ? 'on' : ''}`}>
            <span className="status-dot" /> {live ? 'Live' : new URLSearchParams(window.location.search).has('nolive') ? 'Polling' : 'Reconnecting'}
          </span>
          <button className="btn" onClick={verify}><Icon name="shield-check" size={14} /> Verify chain</button>
          <a className="btn" href="/api/audit/export"><Icon name="file" size={14} /> Export JSONL</a>
        </div>
      </PageHeader>

      <section className="kpi-grid">
        {kpis.map((x) => (
          <div key={x.label} className={`kpi ${x.tone || ''}`}>
            <span className="kpi-icon"><Icon name={x.icon} size={16} /></span>
            <span className="kpi-value">{x.value}</span>
            <span className="kpi-label">{x.label}</span>
          </div>
        ))}
      </section>

      <section className="mon-grid">
        <div className="box">
          <div className="section-head">
            <h2 className="section-title">Alerts</h2>
            <span className={`pill ${critical ? 'pill-bad' : 'pill-muted'}`}>{critical} critical</span>
          </div>
          <ul className="alert-list">
            {alerts.length === 0 && <li className="muted small-text">No alerts yet. Run an attack demo or a scan.</li>}
            {alerts.slice(0, 8).map((a) => (
              <li key={a.seq} className={`alert-item sev-${a.severity}`}>
                <span className={`pill pill-${SEV[a.severity] || 'muted'}`}>{a.severity}</span>
                <span className="alert-title">{a.title}</span>
                <span className="muted small-text">{time(a.ts)}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="box">
          <div className="section-head">
            <h2 className="section-title">Integrity monitor</h2>
            <label className="switch">
              <input type="checkbox" checked={!!scan?.enabled} onChange={(e) => config({ enabled: e.target.checked })} />
              <span>{scan?.enabled ? 'Scheduled' : 'Paused'}</span>
            </label>
          </div>
          <p className="muted small-text">
            Every {scan?.interval_s || 120}s VAJRA reconnects to each MCP server through the sandbox and compares every tool
            definition with the baseline. Any change raises a critical alert.
          </p>
          <dl className="facts">
            <dt>Baseline</dt><dd>{scan?.baseline_tools || 0} tool definitions</dd>
            <dt>Last scan</dt>
            <dd>
              {scan?.last ? `${ago(scan.last.at)}: ${scan.last.tools} tools, ${scan.last.rejected} rejected, ` : 'not yet'}
              {scan?.last && <b className={scan.last.drift.length ? 'text-bad' : 'text-ok'}>{scan.last.drift.length} drift</b>}
            </dd>
            <dt>Next scan</dt><dd>{scan?.enabled && scan?.next_at ? `in ${Math.max(0, Math.round(scan.next_at - Date.now() / 1000))}s` : '-'}</dd>
          </dl>
          {scan?.last?.drift?.length > 0 && (
            <ul className="drift-list">
              {scan.last.drift.map((d) => <li key={d.tool}><Icon name="alert" size={13} /> <code>{d.tool}</code> {d.change}</li>)}
            </ul>
          )}
          <div className="cta">
            <button className="btn primary" onClick={scanNow} disabled={scanning}>
              <Icon name={scanning ? 'activity' : 'refresh'} size={14} /> {scanning ? 'Scanning' : 'Scan now'}
            </button>
            <button className={`btn ${scan?.simulate_drift ? 'danger' : ''}`} onClick={() => config({ simulate_drift: !scan?.simulate_drift })}>
              <Icon name="alert" size={14} /> {scan?.simulate_drift ? 'Tool change simulated' : 'Simulate a tool change'}
            </button>
            <button className="btn ghost" onClick={() => config({ reset_baseline: true, simulate_drift: false })}>
              <Icon name="refresh" size={14} /> Reset baseline
            </button>
          </div>
        </div>

        <div className="box chain-card">
          <h2 className="section-title">Audit chain</h2>
          {chain == null ? (
            <p className="muted small-text">Verifying</p>
          ) : chain.ok ? (
            <div className="chain ok">
              <Icon name="shield-check" size={22} />
              <div>
                <b>Verified</b>
                <span>{chain.records} records, unbroken hash chain</span>
                {chain.head && <code>head {chain.head.slice(0, 16)}</code>}
              </div>
            </div>
          ) : (
            <div className="chain bad">
              <Icon name="alert" size={22} />
              <div>
                <b>Tampering detected</b>
                <span>Record #{chain.broken_at}: {chain.reason}</span>
              </div>
            </div>
          )}
          <p className="muted small-text">
            Each record stores the SHA-256 of the previous one. Editing or deleting any past record breaks the chain at that
            point. Records hold metadata only; untrusted content is never written.
          </p>
        </div>
      </section>

      <section className="box">
        <div className="section-head">
          <h2 className="section-title">Audit trail</h2>
          <div className="trail-tools">
            <div className="filter-chips">
              {FILTERS.map(([id, label]) => (
                <button key={id} className={`example ${filter === id ? 'on' : ''}`} onClick={() => setFilter(id)}>{label}</button>
              ))}
            </div>
            <label className="search">
              <Icon name="search" size={14} />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by tool, reason, session" />
            </label>
          </div>
        </div>
        <div className="trail-wrap">
          <table className="data-table trail">
            <thead>
              <tr><th className="num">#</th><th>Time</th><th>Event</th><th>Subject</th><th>Details</th><th>Hash</th></tr>
            </thead>
            <tbody>
              {shown.length === 0 && <tr><td colSpan={6} className="muted">No records match.</td></tr>}
              {shown.slice(0, 250).map((r) => {
                const meta = KIND[r.kind] || { label: r.kind, tone: 'muted' }
                return (
                  <tr key={r.seq} className={fresh.current.has(r.seq) ? 'fresh' : ''}>
                    <td className="num muted">{r.seq}</td>
                    <td className="muted nowrap">{time(r.ts)}</td>
                    <td><span className={`pill pill-${r.kind === 'alert' ? SEV[r.severity] || 'bad' : meta.tone}`}>{meta.label}</span></td>
                    <td className="subject">{subject(r)}</td>
                    <td className="detail">{details(r)}</td>
                    <td><code className="hash" title={r.hash}>{r.hash?.slice(0, 10)}</code></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
