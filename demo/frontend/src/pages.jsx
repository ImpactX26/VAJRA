import { useEffect, useState } from 'react'
import { FlowHero } from './components/FlowHero.jsx'
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
  return `${ok.filter((r) => r[key]).length}/${ok.length}`
}

export function HomePage({ scenarios }) {
  const results = useResults()
  const bench = results.find((r) => r.id === 'evaluation_groq_agentdojo')
  return (
    <div className="page">
      <section className="home-hero">
        <h1>VAJRA</h1>
        <p className="lead">
          Zero-trust MCP proxy. It stops prompt injection <em>architecturally</em>, with taint tracking, a tool-less
          quarantine LLM and deterministic policy. No AI classifiers involved.
        </p>
        <div className="cta">
          <a className="btn primary" href={href.attacks}>▶ Watch the demos</a>
          <a className="btn" href="#/sandbox">🛡️ Sandbox</a>
          <a className="btn" href={href.how}>How it works</a>
        </div>
      </section>

      <section className="box hero-visual">
        <FlowHero />
      </section>

      {bench && (
        <a className="stat-strip" href={href.results}>
          <span className="stat bad">{rate(bench.runs, 'unprotected', 'attack_succeeded')}<small>without VAJRA</small></span>
          <span className="stat good">{rate(bench.runs, 'protected', 'attack_succeeded')}<small>with VAJRA</small></span>
          <span className="stat-note">AgentDojo benchmark, live model ({bench.meta.model}). See all results →</span>
        </a>
      )}

      <section className="explore">
        <a className="tile" href={href.attacks}><b>🎯 Attacks</b><span>{scenarios.length} live demos</span></a>
        <a className="tile" href="#/sandbox"><b>🛡️ Sandbox</b><span>Unsafe tools burned on import</span></a>
        <a className="tile" href={href.how}><b>⚙️ How it works</b><span>The layers of VAJRA</span></a>
        <a className="tile" href={href.anatomy()}><b>🔬 Attack anatomy</b><span>Each attack, layer by layer</span></a>
        <a className="tile" href={href.results}><b>📊 Results</b><span>Measured runs</span></a>
      </section>
    </div>
  )
}

export function AttacksPage({ scenarios }) {
  return (
    <div className="page">
      <h1 className="page-title">Attacks</h1>
      <p className="lead">Pick one to run it with and without VAJRA.</p>
      <section className="attack-grid">
        {scenarios.map((s, i) => (
          <article key={s.id} className="attack-card">
            <span className="scenario-num">Attack {i + 1}</span>
            <h3>{s.title}</h3>
            <p className="attack-type">{s.attack}</p>
            <p>{s.summary}</p>
            <div className="card-actions">
              <a className="btn primary" href={href.demo(s.id)}>▶ Watch demo</a>
              <a className="btn" href={href.anatomy(s.id)}>🔬 Look inside</a>
            </div>
          </article>
        ))}
      </section>
    </div>
  )
}

export function ResultsPage() {
  const results = useResults()
  return (
    <div className="page">
      <h1 className="page-title">Results</h1>
      <p className="lead">
        Recorded with <code>python -m demo.eval</code>. A run counts as hijacked when an email reached an address that
        did not come from the user (checked from the real outbox).
      </p>
      {!results.length && <p className="muted">No recorded results found in docs/.</p>}
      {results.map((r) => (
        <section key={r.id} className="box result-card">
          <h3>{r.meta.model}</h3>
          <p className="muted">{r.meta.date} · {r.meta.repeats} repeat(s) per scenario</p>
          <div className="result-head">
            <span className="stat bad">{rate(r.runs, 'unprotected', 'attack_succeeded')}<small>hijacked without VAJRA</small></span>
            <span className="stat good">{rate(r.runs, 'protected', 'attack_succeeded')}<small>hijacked with VAJRA</small></span>
          </div>
          <table className="plain-table">
            <thead>
              <tr><th>Attack</th><th>Mode</th><th>Outcome</th><th>Blocked</th><th>Withheld</th></tr>
            </thead>
            <tbody>
              {r.runs.map((x, i) => (
                <tr key={i} className={x.attack_succeeded ? 'row-bad' : ''}>
                  <td>{x.scenario}</td>
                  <td>{x.mode === 'protected' ? 'With VAJRA' : 'Without'}</td>
                  <td>{x.error ? 'error (excluded)' : x.attack_succeeded ? 'hijacked' : x.status}</td>
                  <td>{x.blocked}</td>
                  <td>{x.withheld}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </div>
  )
}
