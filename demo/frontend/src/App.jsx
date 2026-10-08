import { useEffect, useState } from 'react'
import { InjectionsPage } from './components/InjectionsPage.jsx'
import { FileViewer, RunPanel, ScenarioPicker } from './components/Panels.jsx'
import { useRun } from './useRun.js'

const SPEEDS = { Slow: 1400, Normal: 750, Fast: 250 }
const PAGES = { '#/': 'Live demo', '#/injections': 'Injection anatomy' }
const currentPage = () => (PAGES[window.location.hash] ? window.location.hash : '#/')

export default function App() {
  const [status, setStatus] = useState(null)
  const [scenarios, setScenarios] = useState([])
  const [selected, setSelected] = useState(null)
  const [provider, setProvider] = useState('scripted')
  const [model, setModel] = useState('')
  const [speed, setSpeed] = useState('Normal')
  const [paused, setPaused] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [page, setPage] = useState(currentPage)
  const unprotected = useRun(SPEEDS[speed], paused)
  const protectedRun = useRun(SPEEDS[speed], paused)

  useEffect(() => {
    Promise.all([fetch('/api/status').then((r) => r.json()), fetch('/api/scenarios').then((r) => r.json())])
      .then(([st, sc]) => {
        setStatus(st)
        setScenarios(sc)
        setSelected(sc[0]?.id)
        if (st.groq_available) {
          setProvider('groq')
          setModel(st.groq_model)
        }
      })
      .catch(() => setLoadError('Cannot reach the demo backend. Start it with: python -m demo.backend'))
  }, [])

  useEffect(() => {
    const onHash = () => {
      setPage(currentPage())
      window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const scenario = scenarios.find((s) => s.id === selected)
  const busy = unprotected.phase === 'running' || protectedRun.phase === 'running'
  const params = (mode) => ({ scenario: selected, mode, provider, ...(provider === 'groq' ? { model } : {}) })
  const providerLabel = provider === 'groq' ? `Groq · ${model}` : 'offline gullible LLM'

  const selectScenario = (id) => {
    unprotected.reset()
    protectedRun.reset()
    setSelected(id)
  }
  const runBoth = async () => {
    protectedRun.reset()
    await unprotected.start(params('unprotected'))
    await protectedRun.start(params('protected'))
  }
  // ?autorun=<scenario-id>&provider=scripted|groq&speed=Fast — hands-free replay (kiosk / screen recording).
  const [autorun] = useState(() => new URLSearchParams(window.location.search))
  useEffect(() => {
    const id = autorun.get('autorun')
    if (!id || !scenario || unprotected.phase !== 'idle') return
    // Apply one setting per render so runBoth() below sees the updated state.
    const wantProvider = autorun.get('provider')
    const wantSpeed = autorun.get('speed')
    if (wantProvider && wantProvider !== provider) return setProvider(wantProvider)
    if (SPEEDS[wantSpeed] && wantSpeed !== speed) return setSpeed(wantSpeed)
    if (scenarios.some((s) => s.id === id) && id !== selected) return setSelected(id)
    autorun.delete('autorun')
    setTimeout(runBoth, 0)
  })

  // From the anatomy page: jump to the live demo and run both agents on that attack.
  const runLive = (id) => {
    selectScenario(id)
    autorun.set('autorun', id)
    window.location.hash = '#/'
  }

  const step = () => {
    unprotected.step()
    protectedRun.step()
  }

  if (loadError) return <div className="fatal">{loadError}</div>
  if (!scenario) return <div className="fatal muted">Loading…</div>

  return (
    <div className="app">
      <header className="hero">
        <div>
          <h1><span className="logo">⚡</span> VAJRA</h1>
          <nav className="nav">
            {Object.entries(PAGES).map(([hash, label]) => (
              <a key={hash} href={hash} className={page === hash ? 'active' : ''}>{label}</a>
            ))}
          </nav>
          <p className="tagline">
            Zero-trust MCP proxy. It stops prompt injection <em>architecturally</em>, with taint tracking,
            a tool-less quarantine LLM and deterministic policy. No AI classifiers involved.
          </p>
        </div>
        {page === '#/' && <div className="controls">
          <label>
            LLM
            <select value={provider} onChange={(e) => setProvider(e.target.value)} disabled={busy}>
              <option value="groq" disabled={!status?.groq_available}>
                Groq (live){status?.groq_available ? '' : ': set GROQ_API_KEY'}
              </option>
              <option value="scripted">Offline: worst-case gullible LLM</option>
            </select>
          </label>
          {provider === 'groq' && (
            <label>
              Model
              <select value={model} onChange={(e) => setModel(e.target.value)} disabled={busy}>
                {status.groq_models.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </label>
          )}
          <label>
            Replay speed
            <select value={speed} onChange={(e) => setSpeed(e.target.value)}>
              {Object.keys(SPEEDS).map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <button onClick={() => setPaused((p) => !p)}>{paused ? '▶ Resume' : '⏸ Pause'}</button>
          <button onClick={step} disabled={!paused}>⏭ Step</button>
        </div>}
      </header>

      {page === '#/injections' ? (
        <InjectionsPage scenarios={scenarios} onRunLive={runLive} />
      ) : (
        <>

        <ScenarioPicker scenarios={scenarios} selected={selected} onSelect={selectScenario} disabled={busy} />

        <section className="scenario-detail">
          <div className="scenario-text">
            <h2>{scenario.title}</h2>
            <p className="attack-type">{scenario.attack}</p>
            <p>{scenario.summary}</p>
            {scenario.source && (
              <p className="source-badge">
                📚 Source:{' '}
                <a href={`${scenario.source.url}/tree/${scenario.source.commit}`} target="_blank" rel="noreferrer">
                  {scenario.source.name}
                </a>
                <span>{scenario.source.details}</span>
              </p>
            )}
            <div className="task">
              <span className="task-label">User task</span>
              <p>“{scenario.task}”</p>
            </div>
            <button className="run-both" onClick={runBoth} disabled={busy}>
              ▶ Run both agents (without VAJRA, then with VAJRA)
            </button>
          </div>
          <FileViewer key={scenario.id} scenario={scenario} />
        </section>

        <div className="panels">
          <RunPanel
            mode="unprotected"
            run={unprotected}
            scenario={scenario}
            disabled={busy}
            providerLabel={providerLabel}
            onRun={() => unprotected.start(params('unprotected'))}
          />
          <RunPanel
            mode="protected"
            run={protectedRun}
            scenario={scenario}
            disabled={busy}
            providerLabel={providerLabel}
            onRun={() => protectedRun.start(params('protected'))}
          />
        </div>

        </>
      )}

      <footer className="legend">
        <h3>How VAJRA stops the attack</h3>
        <ol>
          <li><b>Taint tracking.</b> Every MCP tool result is labelled trusted or untrusted when it arrives. Labels propagate through every call and can only rise.</li>
          <li><b>Opaque handles.</b> Untrusted output is withheld. The planner LLM receives only <code>$vajra:h_…</code>, so injected text never enters its context.</li>
          <li><b>Dual-LLM quarantine.</b> A separate reader LLM processes untrusted data. It has zero tool access, and its output is stored as a new tainted handle.</li>
          <li><b>Deterministic policy.</b> Per-argument rules enforced in code. Untrusted data may fill an email <i>body</i>, never a <i>recipient</i>.</li>
          <li className="muted"><b>Planned:</b> capability tokens and a constrained action grammar.</li>
        </ol>
      </footer>
    </div>
  )
}
