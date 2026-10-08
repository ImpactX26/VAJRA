import { useEffect, useState } from 'react'
import { Icon } from './components/Icon.jsx'
import { InjectionsPage } from './components/InjectionsPage.jsx'
import { MonitorPage } from './components/MonitorPage.jsx'
import { ConvertPage } from './components/ConvertPage.jsx'
import { FileViewer, RunPanel, SourceEvidence } from './components/Panels.jsx'
import { SandboxPage } from './components/SandboxPage.jsx'
import { ThreatsPage } from './components/ThreatsPage.jsx'
import { AttacksPage, HomePage, HowPage, ResultsPage } from './pages.jsx'
import { href, useRoute } from './router.js'
import { useRun } from './useRun.js'

const SPEEDS = { Slow: 1400, Normal: 750, Fast: 250 }
const NAV = [
  ['home', 'Overview', href.home],
  ['attacks', 'Attacks', href.attacks],
  ['threats', 'Threats', '#/threats'],
  ['convert', 'Secure convert', '#/convert'],
  ['sandbox', 'Sandbox', '#/sandbox'],
  ['monitor', 'Monitor', '#/monitor'],
  ['how', 'How it works', href.how],
  ['anatomy', 'Anatomy', href.anatomy()],
  ['results', 'Results', href.results],
]

function Logo() {
  return (
    <svg className="logo-mark" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7L16 2z" fill="currentColor" opacity=".15" />
      <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7L16 2z" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M17.5 8 11 17h5l-1.5 7 6.5-9h-5l1.5-7z" fill="currentColor" />
    </svg>
  )
}

export function RunControls({ provider, setProvider, speed, setSpeed, busy, groqAvailable }) {
  return (
    <>
      <div className="seg" role="group" aria-label="Model">
        <button className={provider === 'groq' ? 'on' : ''} disabled={busy || !groqAvailable} onClick={() => setProvider('groq')}>
          <Icon name="globe" size={13} /> Live model
        </button>
        <button className={provider === 'scripted' ? 'on' : ''} disabled={busy} onClick={() => setProvider('scripted')}>
          <Icon name="cpu" size={13} /> Offline model
        </button>
      </div>
      <div className="seg" role="group" aria-label="Replay speed">
        {Object.keys(SPEEDS).map((s) => (
          <button key={s} className={speed === s ? 'on' : ''} onClick={() => setSpeed(s)}>{s}</button>
        ))}
      </div>
    </>
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

  // Every page starts with clean runs.
  const demoId = route.page === 'demo' ? route.id : null
  useEffect(() => {
    unprotected.reset()
    protectedRun.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.page, route.id])

  const scenario = scenarios.find((s) => s.id === demoId)
  const busy = unprotected.phase === 'running' || protectedRun.phase === 'running'
  const params = (mode) => ({ scenario: demoId, mode, provider })
  const providerLabel = provider === 'groq' ? `Live · ${status?.groq_model}` : 'Offline worst-case model'
  async function runBoth() {
    protectedRun.reset()
    await unprotected.start(params('unprotected'))
    await protectedRun.start(params('protected'))
  }

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

  // Keyboard shortcuts on demo pages: R run both, Space pause/resume, N next step while paused.
  useEffect(() => {
    if (route.page !== 'demo') return undefined
    const onKey = (e) => {
      if (e.target.closest('input, textarea, select') || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'r' && !busy) runBoth()
      else if (e.key === ' ') {
        e.preventDefault()
        setPaused((p) => !p)
      } else if (e.key === 'n' && paused) {
        unprotected.step()
        protectedRun.step()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  if (loadError) return <div className="fatal"><Icon name="alert" size={18} /> {loadError}</div>
  if (!scenarios.length) return <div className="fatal muted"><span className="spinner" /> Loading</div>

  const controls = (
    <RunControls provider={provider} setProvider={setProvider} speed={speed} setSpeed={setSpeed} busy={busy}
      groqAvailable={status?.groq_available} />
  )
  const active = route.page === 'demo' ? 'attacks' : route.page
  let body
  if (route.page === 'attacks') body = <AttacksPage scenarios={scenarios} />
  else if (route.page === 'sandbox') body = <SandboxPage />
  else if (route.page === 'monitor') body = <MonitorPage />
  else if (route.page === 'threats') body = <ThreatsPage />
  else if (route.page === 'convert') body = <ConvertPage />
  else if (route.page === 'how') body = <HowPage />
  else if (route.page === 'anatomy') body = <InjectionsPage scenarios={scenarios} currentId={route.id} />
  else if (route.page === 'results') body = <ResultsPage />
  else if (route.page === 'demo' && scenario) {
    const i = scenarios.indexOf(scenario)
    const next = scenarios[(i + 1) % scenarios.length]
    body = (
      <div className="page">
        <nav className="crumbs" aria-label="Breadcrumb">
          <a href={href.attacks}>Attacks</a>
          <Icon name="chevron-right" size={13} />
          <span>{scenario.title}</span>
        </nav>
        <section className="demo-head box">
          <div className="demo-intro">
            <span className="eyebrow">Attack {i + 1}</span>
            <h1 className="page-title">{scenario.title}</h1>
            <p className="attack-type">{scenario.attack}</p>
            <p>{scenario.summary}</p>
            <div className="task">
              <span className="task-label"><Icon name="user" size={13} /> Request from {scenario.user_name}</span>
              <p>{scenario.task}</p>
            </div>
            <SourceEvidence source={scenario.source} />
          </div>
          <details className="file-details collapsible" open>
            <summary>
              <Icon name="chevron-right" size={14} className="chev" />
              <Icon name="file" size={14} /> Input the assistant will read
            </summary>
            <FileViewer key={scenario.id} scenario={scenario} />
          </details>
        </section>

        <section className="runbar box">
          <button className="btn primary lg" onClick={runBoth} disabled={busy}>
            <Icon name="play" size={15} /> Run both <kbd>R</kbd>
          </button>
          {controls}
          <div className="seg">
            <button onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
              <Icon name={paused ? 'play' : 'pause'} size={13} /> {paused ? 'Resume' : 'Pause'}
            </button>
            <button disabled={!paused} onClick={() => { unprotected.step(); protectedRun.step() }}>
              <Icon name="skip-forward" size={13} /> Step
            </button>
          </div>
          <span className="muted runbar-model"><Icon name="cpu" size={13} /> {providerLabel}</span>
        </section>

        <div className="panels">
          <RunPanel mode="unprotected" run={unprotected} scenario={scenario} disabled={busy} providerLabel={providerLabel}
            onRun={() => unprotected.start(params('unprotected'))} />
          <RunPanel mode="protected" run={protectedRun} scenario={scenario} disabled={busy} providerLabel={providerLabel}
            onRun={() => protectedRun.start(params('protected'))} />
        </div>

        <nav className="pager">
          <a className="btn ghost" href={href.anatomy(scenario.id)}><Icon name="search" size={14} /> Anatomy of this attack</a>
          <a className="btn" href={href.demo(next.id)}>Next: {next.title} <Icon name="arrow-right" size={14} /></a>
        </nav>
      </div>
    )
  } else body = <HomePage />

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href={href.home}><Logo /> VAJRA</a>
          <nav className="nav" aria-label="Main">
            {NAV.map(([id, label, link]) => (
              <a key={id} href={link} className={active === id ? 'active' : ''} aria-current={active === id ? 'page' : undefined}>
                {label}
              </a>
            ))}
          </nav>
          <span className={`model-badge ${status?.groq_available ? 'on' : ''}`} title="Planner and reader model">
            <span className="status-dot" /> {status?.groq_model || 'offline'}
          </span>
        </div>
      </header>
      <main key={`${route.page}/${route.id}`} className="app">{body}</main>
      <footer className="foot">
        <div className="foot-inner">
          <span>VAJRA · zero-trust MCP proxy</span>
          <span className="muted">Deterministic policy · Taint tracking · OS sandboxing</span>
        </div>
      </footer>
    </div>
  )
}
