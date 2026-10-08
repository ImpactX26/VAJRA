import { useEffect, useState } from 'react'
import { InjectionsPage } from './components/InjectionsPage.jsx'
import { FileViewer, RunPanel, SourceEvidence } from './components/Panels.jsx'
import { Playground } from './components/Playground.jsx'
import { LAYERS } from './injectionGuide.js'
import { AttacksPage, HomePage, ResultsPage } from './pages.jsx'
import { href, useRoute } from './router.js'
import { useRun } from './useRun.js'

const SPEEDS = { Slow: 1400, Normal: 750, Fast: 250 }
const NAV = [
  ['home', 'Home', href.home],
  ['attacks', 'Attacks', href.attacks],
  ['try', 'Try VAJRA', '#/try'],
  ['how', 'How it works', href.how],
  ['anatomy', 'Attack anatomy', href.anatomy()],
  ['results', 'Results', href.results],
]

function HowPage() {
  return (
    <div className="page">
      <h1 className="page-title">How it works</h1>
      <p className="lead">Every tool result passes through these layers, in this order.</p>
      <ol className="how-steps">
        {LAYERS.filter((l) => !l.planned).map((l, i) => (
          <li key={l.id} className="box how-card" style={{ animationDelay: `${i * 0.08}s` }}>
            <span className="how-num">{i + 1}</span>
            <div>
              <h3>{l.name}</h3>
              <p>{l.what}</p>
              <code className="muted">{l.code}</code>
            </div>
          </li>
        ))}
      </ol>
      <h2 className="section-title">Planned</h2>
      <ul className="how-planned">
        {LAYERS.filter((l) => l.planned).map((l) => <li key={l.id}><b>{l.name}.</b> {l.what}</li>)}
      </ul>
    </div>
  )
}

function TryPage() {
  return (
    <div className="page">
      <h1 className="page-title">Try VAJRA</h1>
      <p className="lead">Run any text through VAJRA’s three checks and watch each decision.</p>
      <Playground />
    </div>
  )
}

export default function App() {
  const route = useRoute()
  const [status, setStatus] = useState(null)
  const [scenarios, setScenarios] = useState([])
  const [provider, setProvider] = useState('scripted')
  const [speed, setSpeed] = useState('Normal')
  const [paused, setPaused] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const unprotected = useRun(SPEEDS[speed], paused)
  const protectedRun = useRun(SPEEDS[speed], paused)

  useEffect(() => {
    Promise.all([fetch('/api/status').then((r) => r.json()), fetch('/api/scenarios').then((r) => r.json())])
      .then(([st, sc]) => {
        setStatus(st)
        setScenarios(sc)
        if (st.groq_available) setProvider('groq')
      })
      .catch(() => setLoadError('Cannot reach the demo backend. Start it with: python -m demo.backend'))
  }, [])

  // A new demo page starts clean.
  const demoId = route.page === 'demo' ? route.id : null
  useEffect(() => {
    unprotected.reset()
    protectedRun.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demoId])

  // ?autorun=<id>&provider=…&speed=… : open that demo and run it hands-free.
  const [autorun] = useState(() => new URLSearchParams(window.location.search))
  useEffect(() => {
    const id = autorun.get('autorun')
    if (!id || !scenarios.length) return
    if (autorun.get('provider') && autorun.get('provider') !== provider) return setProvider(autorun.get('provider'))
    if (SPEEDS[autorun.get('speed')] && autorun.get('speed') !== speed) return setSpeed(autorun.get('speed'))
    if (demoId !== id) {
      window.location.hash = href.demo(id)
      return
    }
    autorun.delete('autorun')
    setTimeout(runBoth, 0)
  })

  const scenario = scenarios.find((s) => s.id === demoId)
  const busy = unprotected.phase === 'running' || protectedRun.phase === 'running'
  const params = (mode) => ({ scenario: demoId, mode, provider })
  const providerLabel = provider === 'groq' ? `Live · ${status?.groq_model}` : 'Offline worst-case AI'
  async function runBoth() {
    protectedRun.reset()
    await unprotected.start(params('unprotected'))
    await protectedRun.start(params('protected'))
  }

  if (loadError) return <div className="fatal">{loadError}</div>
  if (!scenarios.length) return <div className="fatal muted">Loading…</div>

  const active = route.page === 'demo' ? 'attacks' : route.page
  let body
  if (route.page === 'attacks') body = <AttacksPage scenarios={scenarios} />
  else if (route.page === 'try') body = <TryPage />
  else if (route.page === 'how') body = <HowPage />
  else if (route.page === 'anatomy') body = <InjectionsPage scenarios={scenarios} currentId={route.id} />
  else if (route.page === 'results') body = <ResultsPage />
  else if (route.page === 'demo' && scenario) {
    const i = scenarios.indexOf(scenario)
    const next = scenarios[(i + 1) % scenarios.length]
    body = (
      <div className="page">
        <p className="crumbs"><a href={href.attacks}>Attacks</a> › {scenario.title}</p>
        <section className="demo-head box">
          <div>
            <span className="scenario-num">Attack {i + 1}</span>
            <h1 className="page-title">{scenario.title}</h1>
            <p className="attack-type">{scenario.attack}</p>
            <p>{scenario.summary}</p>
            <SourceEvidence source={scenario.source} />
            <div className="task">
              <span className="task-label">What {scenario.user_name} asks the assistant</span>
              <p>“{scenario.task}”</p>
            </div>
          </div>
          <details className="file-details">
            <summary>📄 See the file the assistant will read</summary>
            <FileViewer key={scenario.id} scenario={scenario} />
          </details>
        </section>

        <section className="runbar box">
          <button className="btn primary big" onClick={runBoth} disabled={busy}>▶ Run both</button>
          <div className="seg">
            <button className={provider === 'groq' ? 'on' : ''} disabled={busy || !status?.groq_available} onClick={() => setProvider('groq')}>
              🌐 Live AI
            </button>
            <button className={provider === 'scripted' ? 'on' : ''} disabled={busy} onClick={() => setProvider('scripted')}>
              💻 Offline AI
            </button>
          </div>
          <div className="seg">
            {Object.keys(SPEEDS).map((s) => (
              <button key={s} className={speed === s ? 'on' : ''} onClick={() => setSpeed(s)}>{s}</button>
            ))}
          </div>
          <button className="btn" onClick={() => setPaused((p) => !p)}>{paused ? '▶ Resume' : '⏸ Pause'}</button>
          <button className="btn" disabled={!paused} onClick={() => { unprotected.step(); protectedRun.step() }}>⏭ Step</button>
          <span className="muted runbar-model">{providerLabel}</span>
        </section>

        <div className="panels">
          <RunPanel mode="unprotected" run={unprotected} scenario={scenario} disabled={busy} providerLabel={providerLabel}
            onRun={() => unprotected.start(params('unprotected'))} />
          <RunPanel mode="protected" run={protectedRun} scenario={scenario} disabled={busy} providerLabel={providerLabel}
            onRun={() => protectedRun.start(params('protected'))} />
        </div>

        <nav className="pager">
          <a className="btn" href={href.anatomy(scenario.id)}>🔬 Look inside this attack</a>
          <a className="btn primary" href={href.demo(next.id)}>Next: {next.title} →</a>
        </nav>
      </div>
    )
  } else body = <HomePage scenarios={scenarios} />

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href={href.home}><span className="logo">⚡</span> VAJRA</a>
        <nav className="nav">
          {NAV.map(([id, label, link]) => (
            <a key={id} href={link} className={active === id ? 'active' : ''}>{label}</a>
          ))}
        </nav>
      </header>
      <main key={`${route.page}/${route.id}`} className="fade-in">{body}</main>
      <footer className="foot muted">VAJRA · zero-trust MCP proxy · live model: {status?.groq_model}</footer>
    </div>
  )
}
