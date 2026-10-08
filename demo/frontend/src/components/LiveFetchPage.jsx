import { useEffect, useState } from 'react'
import { RunPanel } from './Panels.jsx'
import { WinSandboxChip, useWinSandbox } from './WinSandboxPanel.jsx'

// Real-world demo: the user types a request about a page on the separate demo
// website. The page is fetched over real HTTP through the web MCP server; with
// VAJRA, hidden content is burned in the sandbox and a clean answer is delivered.

const DEFAULT_PROMPT = 'Summarize the setup steps from http://127.0.0.1:8090/setup'

export function LiveFetchPage({ scenarios, unprotected, protectedRun, provider, providerLabel, controls }) {
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT)
  const [site, setSite] = useState(null)
  const [vm] = useWinSandbox()
  useEffect(() => {
    fetch('/api/site').then((r) => r.json()).then(setSite).catch(() => setSite({ up: false }))
  }, [])

  const base = scenarios.find((s) => s.id === 'malicious-webpage')
  const scenario = { ...base, id: 'live', title: 'Live web fetch', task: prompt, expectation: {} }
  const busy = unprotected.phase === 'running' || protectedRun.phase === 'running'
  const params = (mode) => ({ scenario: 'live', prompt, mode, provider })
  const runBoth = async () => {
    protectedRun.reset()
    await unprotected.start(params('unprotected'))
    await protectedRun.start(params('protected'))
  }

  // ?autoask=1 runs the default request once the site is online (hands-free demo / recording).
  const [autoask, setAutoask] = useState(() => new URLSearchParams(window.location.search).has('autoask'))
  useEffect(() => {
    if (autoask && site?.up) {
      setAutoask(false)
      runBoth()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoask, site])

  return (
    <div className="page">
      <h1 className="page-title">Live fetch</h1>
      <p className="lead">Ask the assistant about a real web page. The page is fetched live from a separate website.</p>

      <section className="box live-site">
        <span className={`dot ${site?.up ? 'up' : 'down'}`} />
        <span>
          Demo website <code>{site?.url || 'http://127.0.0.1:8090/setup'}</code>{' '}
          {site == null ? 'checking…' : site.up ? 'is online' : 'is offline. Start it with python -m demo.backend.site_server'}
        </span>
        {site?.up && <a className="btn" href={site.url} target="_blank" rel="noreferrer">Open the page ↗</a>}
        <WinSandboxChip vm={vm} />
      </section>

      <section className="box live-ask">
        <label>
          <b>Your request</b>
          <textarea rows={2} value={prompt} onChange={(e) => setPrompt(e.target.value)} disabled={busy} />
        </label>
        <div className="live-actions">
          <button className="btn primary big" onClick={runBoth} disabled={busy || !site?.up}>▶ Ask, with and without VAJRA</button>
          {controls}
          <span className="muted runbar-model">{providerLabel}</span>
        </div>
      </section>

      <div className="panels">
        <RunPanel mode="unprotected" run={unprotected} scenario={scenario} disabled={busy || !site?.up} providerLabel={providerLabel}
          onRun={() => unprotected.start(params('unprotected'))} />
        <RunPanel mode="protected" run={protectedRun} scenario={scenario} disabled={busy || !site?.up} providerLabel={providerLabel}
          onRun={() => protectedRun.start(params('protected'))} />
      </div>
    </div>
  )
}
