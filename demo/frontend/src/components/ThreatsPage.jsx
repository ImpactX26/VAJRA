import { useEffect, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { href } from '../router.js'
import { Icon } from './Icon.jsx'

// Threat coverage: the five threats VAJRA is built against, the layer that handles each,
// and a live self-test that exercises the real policy code for every one.

const ABOUT = {
  indirect: {
    icon: 'file',
    plain: 'Text inside a file, email or web page is written to look like an instruction, and the agent obeys it.',
    how: 'The planner never reads outside content. It gets a sealed handle; a separate reader with no tools summarises it, and hidden parts of web pages are burned first.',
    demo: [href.demo('agentdojo-feedback'), 'Run the AgentDojo attack'],
  },
  poisoning: {
    icon: 'package',
    plain: 'A tool server ships a tool whose description or schema carries hidden or changed instructions.',
    how: 'Every tool passes the admission sandbox before the agent sees it: hidden characters, malformed schemas and definitions that changed after review are rejected.',
    demo: ['#/sandbox', 'Open the tool sandbox'],
  },
  lateral: {
    icon: 'layers',
    plain: 'One server impersonates another server’s tool, or data from one tool is pushed into a more powerful one.',
    how: 'Tool names must be unique across servers, and each argument lists which servers its outside data may come from.',
    demo: ['#/sandbox', 'See shadowing rejected'],
  },
  exfiltration: {
    icon: 'lock',
    plain: 'Private data the agent has read is sent out through email, a web request or another outbound tool.',
    how: 'Data from sources marked secret carries a secret label that spreads to anything derived from it. Tools that send data out refuse it.',
    demo: ['#/monitor', 'Watch blocks in the audit trail'],
  },
  downstream: {
    icon: 'server',
    plain: 'A tool argument smuggles extra syntax that a shell, database or mail server will act on.',
    how: 'Arguments that reach a downstream system must fully match a fixed format, checked after handles are resolved, just before the call.',
    demo: [href.demo('recipient-hijack'), 'Run the recipient attack'],
  },
}

export function ThreatsPage() {
  const [report, setReport] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)

  const run = async () => {
    setRunning(true)
    setError(null)
    try {
      const r = await fetch('/api/selftest')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setReport(await r.json())
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setRunning(false)
    }
  }

  useEffect(() => { run() }, [])

  const checks = report ? report.threats.flatMap((t) => t.checks) : []
  const passed = checks.filter((c) => c.ok).length

  return (
    <div className="page">
      <PageHeader
        eyebrow="Coverage"
        title="Threat coverage"
        lead="Five ways an AI agent can be turned against its user, and the fixed rule in VAJRA that stops each one. The self-test runs the real policy code every time you open this page."
      >
        <div className="thr-actions">
          <button className="btn primary" onClick={run} disabled={running}>
            <Icon name={running ? 'refresh' : 'play'} size={14} /> {running ? 'Running' : 'Run self-test'}
          </button>
          {report && (
            <span className={`thr-score ${report.ok ? 'ok' : 'bad'}`}>
              <Icon name={report.ok ? 'shield-check' : 'shield-alert'} size={15} />
              {passed} of {checks.length} checks passed
              <span className="thr-ms">in {report.ms} ms</span>
            </span>
          )}
          {error && <span className="thr-score bad"><Icon name="alert" size={15} /> Self-test unavailable: {error}</span>}
        </div>
      </PageHeader>

      <div className="thr-grid">
        {(report?.threats || Object.keys(ABOUT).map((id) => ({ id, title: '', checks: [] }))).map((t, i) => {
          const a = ABOUT[t.id] || {}
          const state = !report ? 'pending' : t.ok ? 'ok' : 'bad'
          return (
            <section key={t.id} className={`panel thr-card ${state}`}>
              <div className="thr-head">
                <span className="thr-num">{String(i + 1).padStart(2, '0')}</span>
                <span className="thr-icon"><Icon name={a.icon || 'shield'} size={18} /></span>
                <div className="thr-titles">
                  <h2>{t.title || ' '}</h2>
                  {t.layer && <span className="thr-layer">{t.layer}</span>}
                </div>
                <span className={`thr-status ${state}`}>
                  {state === 'pending' ? 'Checking' : state === 'ok' ? 'Defended' : 'Failing'}
                </span>
              </div>

              <div className="thr-explain">
                <div>
                  <span className="thr-label">The threat</span>
                  <p>{a.plain}</p>
                </div>
                <div>
                  <span className="thr-label">How VAJRA stops it</span>
                  <p>{a.how}</p>
                </div>
              </div>

              <ul className="thr-checks">
                {t.checks.map((c) => (
                  <li key={c.name} className={c.ok ? 'ok' : 'bad'}>
                    <Icon name={c.ok ? 'check-circle' : 'x'} size={15} />
                    <div>
                      <strong>{c.name}</strong>
                      <span>{c.detail}</span>
                    </div>
                  </li>
                ))}
              </ul>

              {a.demo && (
                <a className="thr-link" href={a.demo[0]}>
                  {a.demo[1]} <Icon name="arrow-right" size={14} />
                </a>
              )}
            </section>
          )
        })}
      </div>

      <p className="thr-foot muted">
        None of these checks looks at what the text says. Each one is a rule about where data came from, what
        label it carries, or what shape an argument has, so wording an attack differently does not get around it.
        Each self-test run is written to the audit trail.
      </p>
    </div>
  )
}
