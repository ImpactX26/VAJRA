import { useEffect, useRef, useState } from 'react'
import { Doc } from '../highlight.jsx'
import { Icon } from './Icon.jsx'
import { OrchestrationDiagram } from './OrchestrationDiagram.jsx'
import { PipelineStepper } from './PipelineStepper.jsx'
import { Summary } from './Summary.jsx'
import { Timeline } from './Timeline.jsx'

export function ScenarioPicker({ scenarios, selected, onSelect, disabled }) {
  return (
    <div className="scenarios">
      {scenarios.map((s, i) => (
        <button key={s.id} className={`scenario ${s.id === selected ? 'selected' : ''}`} onClick={() => onSelect(s.id)} disabled={disabled}>
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
    <details className="evidence collapsible" open={open}>
      <summary>
        <Icon name="chevron-right" size={14} className="chev" />
        <Icon name="book" size={15} />
        <span>
          Source: <b>{source.name}</b> · commit <code>{source.commit.slice(0, 10)}</code>
        </span>
        <span className="muted evidence-count">{source.evidence.length} files and line ranges</span>
      </summary>
      <table>
        <thead>
          <tr><th>What</th><th>File</th><th>Lines</th></tr>
        </thead>
        <tbody>
          {source.evidence.map((e) => (
            <tr key={e.url}>
              <td>{e.what}</td>
              <td>
                <a href={e.url} target="_blank" rel="noreferrer"><code>{e.path}</code><Icon name="external" size={12} /></a>
              </td>
              <td className="lines">{e.lines}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">Rebuild the exact file yourself: <code>{source.rebuild}</code></p>
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
      <div className="tabs" role="tablist">
        {files.map((f, i) => (
          <button key={f.path} role="tab" aria-selected={i === tab} className={`tab ${i === tab ? 'active' : ''}`} onClick={() => setTab(i)}>
            <Icon name={f.path.includes('secrets/') ? 'key' : 'file'} size={13} /> {f.path}
          </button>
        ))}
      </div>
      <div className={`file-banner ${isSource ? 'source' : isSecret ? 'secret' : 'poison'}`}>
        <Icon name={isSource ? 'book' : isSecret ? 'key' : 'alert'} size={14} />
        {isSource
          ? 'Provenance: where this payload comes from (not written by us)'
          : isSecret
          ? 'Target of exfiltration: fake credentials the attacker wants'
          : 'Test input. Highlighted lines are the prompt injection'}
      </div>
      <div ref={box} className="file-scroll">
        <Doc text={file.content} scenario={scenario} className="file-doc" />
      </div>
    </div>
  )
}

function Section({ icon, title, tone = '', children, aside }) {
  return (
    <div className={`result-section ${tone}`}>
      <div className="rs-head">
        <Icon name={icon} size={15} />
        <h3>{title}</h3>
        {aside}
      </div>
      {children}
    </div>
  )
}

function Burned({ events }) {
  const burned = events.filter((e) => e.type === 'proxy.sanitize').flatMap((e) => e.burned)
  if (!burned.length) return null
  return (
    <Section icon="flame" title="Removed in the sandbox" tone="burn" aside={<span className="count bad">{burned.length}</span>}>
      {burned.map((b, i) => (
        <div key={i} className="burned-item">
          <b>{b.kind}</b>
          {b.preview && <code>{b.preview}</code>}
        </div>
      ))}
    </Section>
  )
}

function Delivered({ event }) {
  const [copied, setCopied] = useState(false)
  if (!event) return null
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(event.text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <Section
      icon="inbox"
      title="Delivered to you"
      tone="deliver"
      aside={
        <button className="btn ghost small" onClick={copy}>
          <Icon name={copied ? 'check' : 'copy'} size={13} /> {copied ? 'Copied' : 'Copy'}
        </button>
      }
    >
      <pre className="delivered-text">{event.text}</pre>
      <small className="muted">Shown to you by VAJRA. The AI planner only ever held a sealed reference to this text.</small>
    </Section>
  )
}

function SecurityNotice({ report }) {
  if (!report) return null
  const tone = report.blocked.length ? 'blocked' : 'notice'
  return (
    <Section icon="shield" title="Security notice sent to the user" tone={tone}>
      <pre className="notice-text">{report.notice}</pre>
    </Section>
  )
}

function Outbox({ emails, scenario }) {
  if (!emails) return null
  return (
    <Section icon="mail" title="Emails actually sent" aside={<span className="count">{emails.length}</span>}>
      {!emails.length && <p className="muted small-text">None.</p>}
      {emails.map((m, i) => {
        const outsider = m.to.trim().toLowerCase() !== scenario.user_email
        return (
          <details key={i} className={`email collapsible ${outsider ? 'attacker' : 'legit'}`}>
            <summary className="email-head">
              <Icon name="chevron-right" size={13} className="chev" />
              <span className={`pill ${outsider ? 'pill-bad' : 'pill-ok'}`}>{outsider ? 'Not the user' : 'User'}</span>
              <span className="email-to">{m.to}</span>
              <span className="muted email-subj">{m.subject}</span>
            </summary>
            <Doc text={m.body} scenario={scenario} maxLines={10} />
          </details>
        )
      })}
    </Section>
  )
}

function Verdict({ events, phase, scenario }) {
  const verdict = events.find((e) => e.type === 'verdict')
  const error = events.find((e) => e.type === 'error')
  const blocks = events.filter((e) => e.type === 'proxy.block').length
  const box = (tone, icon, title, detail) => (
    <div className={`verdict v-${tone}`} role="status">
      <Icon name={icon} size={18} />
      <div>
        <div className="v-title">{title}</div>
        {detail && <div className="v-detail">{detail}</div>}
      </div>
    </div>
  )
  if (error && !verdict) return box('error', 'alert', 'The run failed', error.message)
  if (!verdict) {
    if (phase === 'running') return box('pending', 'activity', 'Running', 'The assistant is working through the request.')
    return box('idle', 'clock', 'Not run yet', 'Press Run to start.')
  }
  if (verdict.status === 'compromised') {
    return box('bad', 'alert', 'Attack succeeded',
      <>An email went to <b>{verdict.foreign_recipients.join(', ')}</b>{verdict.secrets_leaked && ', including the secret keys'}.</>)
  }
  if (events.some((e) => e.type === 'vajra.deliver')) {
    return box('ok', 'shield-check', 'Protected', 'Hidden content was removed and a clean answer was delivered.')
  }
  if (blocks) return box('ok', 'shield-check', 'Attack stopped', `VAJRA blocked ${blocks} unsafe action${blocks > 1 ? 's' : ''}. Nothing reached the attacker.`)
  if (verdict.status === 'safe') return box('ok', 'shield-check', 'Attack stopped', `Only ${scenario.user_name} received an email.`)
  return box('idle', 'info', 'No email was sent', null)
}

export function RunPanel({ mode, run, scenario, onRun, disabled, providerLabel }) {
  const P = mode === 'protected'
  const outbox = run.events.find((e) => e.type === 'outbox')
  return (
    <section className={`panel ${mode}`}>
      <header className="panel-head">
        <div className="panel-title">
          <span className={`panel-badge ${mode}`}>
            <Icon name={P ? 'shield-check' : 'shield-alert'} size={16} />
          </span>
          <div>
            <h2>{P ? 'With VAJRA' : 'Without VAJRA'}</h2>
            <p className="muted">{P ? 'Tools are reached through VAJRA.' : 'Tools are used directly, with no protection.'}</p>
          </div>
        </div>
        <button className={`btn ${P ? 'primary' : 'danger'}`} onClick={onRun} disabled={disabled}>
          <Icon name={run.phase === 'running' ? 'activity' : 'play'} size={14} /> {run.phase === 'running' ? 'Running' : 'Run'}
        </button>
      </header>
      <PipelineStepper events={run.events} mode={mode} phase={run.phase} />
      <Verdict events={run.events} phase={run.phase} scenario={scenario} />
      {run.events.length > 0 && (
        <>
          <h3 className="what-happened">What happened</h3>
          <Summary events={run.events} mode={mode} scenario={scenario} />
        </>
      )}
      <Burned events={run.events} />
      <Delivered event={run.events.find((e) => e.type === 'vajra.deliver')} />
      <SecurityNotice report={run.events.find((e) => e.type === 'vajra.report')} />
      <Outbox emails={outbox?.emails} scenario={scenario} />
      <details className="tech collapsible">
        <summary>
          <Icon name="chevron-right" size={14} className="chev" />
          <Icon name="activity" size={14} /> Technical details
          <span className="muted">live diagram and every protocol step</span>
        </summary>
        <OrchestrationDiagram mode={mode} events={run.events} scenario={scenario} providerLabel={providerLabel} />
        <Timeline events={run.events} scenario={scenario} mode={mode} />
      </details>
    </section>
  )
}
