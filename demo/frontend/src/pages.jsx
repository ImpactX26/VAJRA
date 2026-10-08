import { useEffect, useState } from 'react'
import { FlowHero } from './components/FlowHero.jsx'
import { Icon } from './components/Icon.jsx'
import { LAYERS } from './injectionGuide.js'
import { href } from './router.js'

export function useResults() {
  const [results, setResults] = useState([])
  useEffect(() => {
    fetch('/api/results').then((r) => r.json()).then(setResults).catch(() => setResults([]))
  }, [])
  return results
}

export function rate(runs, mode, key) {
  const ok = runs.filter((r) => r.mode === mode && !r.error)
  return { hit: ok.filter((r) => r[key]).length, total: ok.length }
}

function CountUp({ value, duration = 900 }) {
  const [n, setN] = useState(0)
  useEffect(() => {
    let raf
    const start = performance.now()
    const tick = (t) => {
      const p = Math.min(1, (t - start) / duration)
      setN(Math.round(value * (1 - (1 - p) ** 3)))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    const settle = setTimeout(() => setN(value), duration + 150) // always end on the exact value
    return () => {
      cancelAnimationFrame(raf)
      clearTimeout(settle)
    }
  }, [value, duration])
  return n
}

export function PageHeader({ eyebrow, title, lead, children }) {
  return (
    <header className="page-header">
      {eyebrow && <span className="eyebrow">{eyebrow}</span>}
      <h1 className="page-title">{title}</h1>
      {lead && <p className="lead">{lead}</p>}
      {children}
    </header>
  )
}

const FEATURES = [
  { icon: 'target', title: 'Attacks', text: 'Four injection scenarios, run side by side with and without VAJRA.', link: href.attacks },
  { icon: 'shield-check', title: 'Threats', text: 'Five threats, the rule that stops each, and a live self-test.', link: '#/threats' },
  { icon: 'file', title: 'Secure convert', text: 'Image to PDF with the real iLovePDF; unsafe files are burned before download.', link: '#/convert' },
  { icon: 'package', title: 'Sandbox', text: 'Tool admission checks, OS isolation and the Windows Sandbox VM.', link: '#/sandbox' },
  { icon: 'activity', title: 'Monitor', text: 'Live audit trail, alerts and continuous integrity scanning.', link: '#/monitor' },
  { icon: 'layers', title: 'How it works', text: 'The layers every tool result passes through, in order.', link: href.how },
  { icon: 'search', title: 'Attack anatomy', text: 'Each payload and the layer that stops it.', link: href.anatomy() },
  { icon: 'chart', title: 'Results', text: 'Measured runs with a live model and a worst-case model.', link: href.results },
]

export function HomePage() {
  const results = useResults()
  const bench = results.find((r) => r.id === 'evaluation_groq_agentdojo')
  const without = bench && rate(bench.runs, 'unprotected', 'attack_succeeded')
  const withV = bench && rate(bench.runs, 'protected', 'attack_succeeded')
  return (
    <div className="page">
      <section className="home-hero">
        <span className="eyebrow">Zero-trust MCP proxy</span>
        <h1>Security for AI agents that holds even when the model is fooled</h1>
        <p className="lead">
          VAJRA sits between an AI assistant and its tools. It stops prompt injection architecturally, with taint
          tracking, a tool-less quarantine model, OS sandboxing and deterministic policy. No AI classifiers involved.
        </p>
        <div className="cta">
          <a className="btn primary lg" href={href.attacks}><Icon name="play" size={15} /> Watch the demos</a>
          <a className="btn lg" href="#/convert"><Icon name="file" size={15} /> Secure convert</a>
          <a className="btn lg" href={href.how}><Icon name="layers" size={15} /> How it works</a>
        </div>
      </section>

      <section className="box hero-visual">
        <FlowHero />
      </section>

      {bench && (
        <a className="metrics" href={href.results}>
          <div className="metric">
            <span className="metric-value bad"><CountUp value={without.hit} />/{without.total}</span>
            <span className="metric-label">runs hijacked without VAJRA</span>
          </div>
          <div className="metric">
            <span className="metric-value good"><CountUp value={withV.hit} />/{withV.total}</span>
            <span className="metric-label">runs hijacked with VAJRA</span>
          </div>
          <div className="metric-note">
            AgentDojo benchmark payload (ETH Zurich) against a live model, {bench.meta.model}.
            <span className="link-inline">View all results <Icon name="arrow-right" size={14} /></span>
          </div>
        </a>
      )}

      <section className="feature-grid">
        {FEATURES.map((f) => (
          <a key={f.title} className="feature" href={f.link}>
            <span className="feature-icon"><Icon name={f.icon} size={18} /></span>
            <span className="feature-title">{f.title}</span>
            <span className="feature-text">{f.text}</span>
            <span className="feature-go"><Icon name="arrow-right" size={14} /></span>
          </a>
        ))}
      </section>
    </div>
  )
}

export function AttacksPage({ scenarios }) {
  return (
    <div className="page">
      <PageHeader eyebrow="Demonstrations" title="Attacks" lead="Each scenario runs the same assistant twice: once without protection, once through VAJRA." />
      <section className="attack-grid">
        {scenarios.map((s, i) => (
          <article key={s.id} className="attack-card">
            <div className="attack-top">
              <span className="attack-index">{String(i + 1).padStart(2, '0')}</span>
              {s.source && <span className="pill pill-info">Research benchmark</span>}
            </div>
            <h3>{s.title}</h3>
            <p className="attack-type">{s.attack}</p>
            <p className="attack-summary">{s.summary}</p>
            <div className="card-actions">
              <a className="btn primary" href={href.demo(s.id)}><Icon name="play" size={14} /> Run demo</a>
              <a className="btn ghost" href={href.anatomy(s.id)}><Icon name="search" size={14} /> Anatomy</a>
            </div>
          </article>
        ))}
      </section>
    </div>
  )
}

export function HowPage() {
  const built = LAYERS.filter((l) => !l.planned)
  const [open, setOpen] = useState(built[0].id)
  return (
    <div className="page">
      <PageHeader eyebrow="Architecture" title="How it works" lead="Every tool result passes through these layers, in this order. Select a layer for details." />
      <div className="how-layout">
        <ol className="how-rail">
          {built.map((l, i) => (
            <li key={l.id}>
              <button className={`how-item ${open === l.id ? 'on' : ''}`} onClick={() => setOpen(l.id)}>
                <span className="how-num">{i + 1}</span>
                <span>{l.name}</span>
                <Icon name="chevron-right" size={14} className="how-chev" />
              </button>
            </li>
          ))}
        </ol>
        {built.filter((l) => l.id === open).map((l, i) => (
          <article key={l.id} className="box how-detail">
            <span className="eyebrow">Layer {built.indexOf(l) + 1}</span>
            <h2>{l.name}</h2>
            <p>{l.what}</p>
            <div className="code-ref"><Icon name="file" size={14} /> <code>{l.code}</code></div>
          </article>
        ))}
      </div>
      <section className="box planned">
        <h3>Planned</h3>
        <ul>
          {LAYERS.filter((l) => l.planned).map((l) => <li key={l.id}><b>{l.name}.</b> {l.what}</li>)}
        </ul>
      </section>
    </div>
  )
}

export function ResultsPage() {
  const results = useResults()
  return (
    <div className="page">
      <PageHeader
        eyebrow="Evidence"
        title="Results"
        lead="Recorded with python -m demo.eval. A run counts as hijacked when an email reached an address that did not come from the user, checked from the real outbox."
      />
      {!results.length && <p className="muted">No recorded results found in docs/.</p>}
      {results.map((r) => {
        const a = rate(r.runs, 'unprotected', 'attack_succeeded')
        const b = rate(r.runs, 'protected', 'attack_succeeded')
        return (
          <section key={r.id} className="box result-card">
            <div className="result-top">
              <div>
                <h3>{r.meta.model}</h3>
                <p className="muted">{r.meta.date} · {r.meta.repeats} repeat(s) per scenario</p>
              </div>
              <div className="result-stats">
                <div className="metric small"><span className="metric-value bad">{a.hit}/{a.total}</span><span className="metric-label">without VAJRA</span></div>
                <div className="metric small"><span className="metric-value good">{b.hit}/{b.total}</span><span className="metric-label">with VAJRA</span></div>
              </div>
            </div>
            <table className="data-table">
              <thead>
                <tr><th>Attack</th><th>Mode</th><th>Outcome</th><th className="num">Blocked</th><th className="num">Withheld</th></tr>
              </thead>
              <tbody>
                {r.runs.map((x, i) => (
                  <tr key={i}>
                    <td>{x.scenario}</td>
                    <td>{x.mode === 'protected' ? 'With VAJRA' : 'Without'}</td>
                    <td>
                      <span className={`pill ${x.error ? 'pill-muted' : x.attack_succeeded ? 'pill-bad' : 'pill-ok'}`}>
                        {x.error ? 'error (excluded)' : x.attack_succeeded ? 'hijacked' : x.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="num">{x.blocked}</td>
                    <td className="num">{x.withheld}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )
      })}
    </div>
  )
}
