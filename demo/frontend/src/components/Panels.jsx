import { useEffect, useRef, useState } from 'react'
import { Doc } from '../highlight.jsx'
import { OrchestrationDiagram } from './OrchestrationDiagram.jsx'
import { Summary } from './Summary.jsx'
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
      <h3>🛡️ What VAJRA told the user</h3>
      <pre>{report.notice}</pre>
    </div>
  )
}

function Outbox({ emails, scenario }) {
  if (!emails) return null
  return (
    <div className="outbox">
      <h3>📤 Emails that were actually sent</h3>
      {!emails.length && <p className="muted">None.</p>}
      {emails.map((m, i) => {
        const outsider = m.to.trim().toLowerCase() !== scenario.user_email
        return (
          <details key={i} className={`email ${outsider ? 'attacker' : 'legit'}`}>
            <summary className="email-head">
              <span className="email-tag">{outsider ? '🚨 not the user' : '✓ the user'}</span>
              <span>To: <b>{m.to}</b></span>
              <span className="muted">“{m.subject}”</span>
            </summary>
            <Doc text={m.body} scenario={scenario} maxLines={10} />
          </details>
        )
      })}
    </div>
  )
}

function Verdict({ events, phase, mode, scenario }) {
  const verdict = events.find((e) => e.type === 'verdict')
  const error = events.find((e) => e.type === 'error')
  const blocks = events.filter((e) => e.type === 'proxy.block').length
  if (error && !verdict) return <div className="verdict error">💥 The run failed: {error.message}</div>
  if (!verdict) {
    if (phase === 'running') return <div className="verdict pending"><span className="spinner" /> The assistant is working…</div>
    return <div className="verdict idle">Not run yet.</div>
  }
  if (verdict.status === 'compromised') {
    return (
      <div className="verdict compromised">
        🚨 Attack worked: an email went to <b>{verdict.foreign_recipients.join(', ')}</b>
        {verdict.secrets_leaked && <>, including the secret keys</>}
      </div>
    )
  }
  if (blocks) return <div className="verdict safe">🛡️ Attack stopped: VAJRA blocked {blocks} unsafe action{blocks > 1 ? 's' : ''}. Nothing reached the attacker.</div>
  if (verdict.status === 'safe') return <div className="verdict safe">🛡️ Attack stopped: only {scenario.user_name} received an email.</div>
  return <div className="verdict idle">No email was sent.</div>
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
            {P ? 'The assistant’s tools are reached through VAJRA.' : 'The assistant uses its tools directly, with no protection.'}
          </p>
        </div>
        <button className={`run-btn ${mode}`} onClick={onRun} disabled={disabled}>
          {run.phase === 'running' ? 'Running…' : 'Run'}
        </button>
      </header>
      <Verdict events={run.events} phase={run.phase} mode={mode} scenario={scenario} />
      <h3 className="what-happened">What happened</h3>
      <Summary events={run.events} mode={mode} scenario={scenario} />
      {run.phase === 'idle' && <p className="muted">Press Run (or “Run both” above) to see each step here.</p>}
      <SecurityNotice report={run.events.find((e) => e.type === 'vajra.report')} />
      <Outbox emails={outbox?.emails} scenario={scenario} />
      <details className="tech">
        <summary>🔧 Technical details: live diagram and every step</summary>
        <OrchestrationDiagram mode={mode} events={run.events} scenario={scenario} providerLabel={providerLabel} />
        <Timeline events={run.events} scenario={scenario} mode={mode} />
      </details>
    </section>
  )
}
