import { useEffect, useRef, useState } from 'react'
import { Doc } from '../highlight.jsx'
import { OrchestrationDiagram } from './OrchestrationDiagram.jsx'
import { Timeline } from './Timeline.jsx'

export function ScenarioPicker({ scenarios, selected, onSelect, disabled }) {
  return (
    <div className="scenarios">
      {scenarios.map((s, i) => (
        <button
          key={s.id}
          className={`scenario ${s.id === selected ? 'selected' : ''}`}
          onClick={() => onSelect(s.id)}
          disabled={disabled}
        >
          <span className="scenario-num">Attack {i + 1}</span>
          <span className="scenario-title">{s.title}</span>
          <span className="scenario-attack">{s.attack}</span>
        </button>
      ))}
    </div>
  )
}

/** Exact upstream files and line ranges a third-party payload was built from, with pinned links. */
export function SourceEvidence({ source, open = false }) {
  if (!source) return null
  return (
    <details className="evidence" open={open}>
      <summary>
        📚 Source: <b>{source.name}</b> · commit <code>{source.commit.slice(0, 10)}</code>{' '}
        <span className="muted">({source.evidence.length} exact files and lines; click to {open ? 'collapse' : 'expand'})</span>
      </summary>
      <table>
        <thead>
          <tr><th>What</th><th>File</th><th>Lines</th></tr>
        </thead>
        <tbody>
          {source.evidence.map((e) => (
            <tr key={e.url}>
              <td>{e.what}</td>
              <td><a href={e.url} target="_blank" rel="noreferrer"><code>{e.path}</code></a></td>
              <td className="lines">{e.lines}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">
        Rebuild the exact file yourself: <code>{source.rebuild}</code>
      </p>
    </details>
  )
}

export function FileViewer({ scenario }) {
  const [tab, setTab] = useState(0)
  const box = useRef(null)
  const files = scenario.file_contents
  const file = files[Math.min(tab, files.length - 1)]
  const isSecret = file.path.includes('secrets/')
  const isSource = file.path.endsWith('SOURCE.md')

  // Bring the first injected line into view so the audience sees the payload immediately.
  useEffect(() => {
    const el = box.current
    const hit = el?.querySelector('.line-inj')
    if (el) el.scrollTop = hit ? Math.max(0, hit.offsetTop - el.offsetTop - 60) : 0
  }, [tab, scenario.id])
  return (
    <div className="files">
      <div className="tabs">
        {files.map((f, i) => (
          <button key={f.path} className={`tab ${i === tab ? 'active' : ''}`} onClick={() => setTab(i)}>
            {f.path.includes('secrets/') ? '🔑' : '📄'} {f.path}
          </button>
        ))}
      </div>
      <div className={`file-banner ${isSource ? 'source' : isSecret ? 'secret' : 'poison'}`}>
        {isSource
          ? 'Provenance: where this payload comes from (not written by us)'
          : isSecret
          ? 'Target of exfiltration: fake credentials the attacker wants'
          : 'Mock poisoned input. Highlighted lines are the prompt injection'}
      </div>
      <div ref={box} className="file-scroll">
        <Doc text={file.content} scenario={scenario} className="file-doc" />
      </div>
    </div>
  )
}

function SecurityNotice({ report }) {
  if (!report) return null
  const tone = report.blocked.length ? 'blocked' : report.withheld.length ? 'withheld' : 'clean'
  return (
    <div className={`notice ${tone}`}>
      <h3>🛡️ VAJRA security notice (what the user is told)</h3>
      <pre>{report.notice}</pre>
    </div>
  )
}

function Outbox({ emails, scenario }) {
  if (!emails) return null
  return (
    <div className="outbox">
      <h3>📤 Outbox: what actually left the system</h3>
      {!emails.length && <p className="muted">No email was sent.</p>}
      {emails.map((m, i) => {
        const attacker = m.to.trim().toLowerCase() !== scenario.user_email
        return (
          <div key={i} className={`email ${attacker ? 'attacker' : 'legit'}`}>
            <div className="email-head">
              <span className="email-tag">{attacker ? '🚨 attacker' : '✓ legitimate'}</span>
              <span>To: <b>{m.to}</b></span>
              <span className="muted">Subject: {m.subject}</span>
            </div>
            <Doc text={m.body} scenario={scenario} maxLines={10} />
          </div>
        )
      })}
    </div>
  )
}

function Verdict({ events, phase, mode, scenario }) {
  const verdict = events.find((e) => e.type === 'verdict')
  const error = events.find((e) => e.type === 'error')
  const blocks = events.filter((e) => e.type === 'proxy.block').length
  if (error && !verdict) return <div className="verdict error">💥 Run failed: {error.message}</div>
  if (!verdict) {
    if (phase === 'running') return <div className="verdict pending"><span className="spinner" /> Agent running…</div>
    return <div className="verdict idle">Press “Run” to start the {mode === 'protected' ? 'protected' : 'unprotected'} agent.</div>
  }
  if (verdict.status === 'compromised') {
    return (
      <div className="verdict compromised">
        🚨 COMPROMISED: data sent to <b>{verdict.foreign_recipients.join(', ')}</b>
        {verdict.secrets_leaked && <> · <b>API keys leaked</b></>}
      </div>
    )
  }
  if (blocks) return <div className="verdict safe">🛡️ SAFE: VAJRA blocked {blocks} unsafe action{blocks > 1 ? 's' : ''}; nothing reached the attacker</div>
  if (verdict.status === 'safe') return <div className="verdict safe">🛡️ SAFE: injection neutralised; only {scenario.user_email} received mail</div>
  return <div className="verdict idle">No email was sent (the model chose not to act).</div>
}

export function RunPanel({ mode, run, scenario, onRun, disabled, providerLabel }) {
  const P = mode === 'protected'
  const outbox = run.events.find((e) => e.type === 'outbox')
  return (
    <section className={`panel ${mode}`}>
      <header className="panel-head">
        <div>
          <h2>{P ? '🛡️ With VAJRA' : '⚠️ Without VAJRA'}</h2>
          <p className="muted">
            {P
              ? 'Planner → VAJRA proxy → MCP servers. Untrusted data is labelled, withheld and policy-checked.'
              : 'Planner talks to MCP servers directly. Tool output goes straight into the LLM context.'}
          </p>
        </div>
        <button className={`run-btn ${mode}`} onClick={onRun} disabled={disabled}>
          {run.phase === 'running' ? 'Running…' : 'Run'}
        </button>
      </header>
      <p className="expect"><b>Expected:</b> {scenario.expectation[mode]}</p>
      <OrchestrationDiagram mode={mode} events={run.events} scenario={scenario} providerLabel={providerLabel} />
      <Verdict events={run.events} phase={run.phase} mode={mode} scenario={scenario} />
      <SecurityNotice report={run.events.find((e) => e.type === 'vajra.report')} />
      <Timeline events={run.events} scenario={scenario} mode={mode} />
      <Outbox emails={outbox?.emails} scenario={scenario} />
    </section>
  )
}
