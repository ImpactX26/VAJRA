import { useEffect, useState } from 'react'
import { PageHeader } from '../pages.jsx'
import { Icon } from './Icon.jsx'
import { RunPanel } from './Panels.jsx'
import { WinSandboxChip, useWinSandbox } from './WinSandboxPanel.jsx'

// Real-world demo: the user types a request about a page on the separate demo
// website. The page is fetched over real HTTP through the web MCP server; with
// VAJRA, hidden content is removed in the sandbox and a clean answer is delivered.

const SITE = 'http://127.0.0.1:8090/setup'
const EXAMPLES = [
  `Summarize the setup steps from ${SITE}`,
  `What command verifies the install, according to ${SITE}?`,
  `List the environment variables mentioned on ${SITE}`,
]

export function LiveFetchPage({ scenarios, unprotected, protectedRun, provider, providerLabel, controls }) {
  const [prompt, setPrompt] = useState(EXAMPLES[0])
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
  const canRun = !busy && site?.up && prompt.trim()

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
      <PageHeader eyebrow="Real-world test" title="Live fetch" lead="Ask the assistant about a real web page. The page is fetched live from a separate website." />

      <section className="box live-site">
        <span className={`status-dot ${site?.up ? 'up' : site ? 'down' : ''}`} />
        <div className="live-site-text">
          <span className="muted small-text">Target website</span>
          <code>{site?.url || SITE}</code>
        </div>
        <span className={`pill ${site?.up ? 'pill-ok' : 'pill-bad'}`}>
          {site == null ? 'Checking' : site.up ? 'Online' : 'Offline: run python -m demo.backend.site_server'}
        </span>
        {site?.up && (
          <a className="btn ghost small" href={site.url} target="_blank" rel="noreferrer">
            Open page <Icon name="external" size={13} />
          </a>
        )}
        <span className="live-site-vm"><WinSandboxChip vm={vm} /></span>
      </section>

      <section className="box live-ask">
        <label className="field">
          <span className="field-label">Request</span>
          <textarea
            rows={2}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && canRun) runBoth()
            }}
            disabled={busy}
          />
        </label>
        <div className="examples">
          <span className="muted small-text">Examples</span>
          {EXAMPLES.map((ex) => (
            <button key={ex} className={`example ${ex === prompt ? 'on' : ''}`} onClick={() => setPrompt(ex)} disabled={busy}>
              {ex.replace(` ${SITE}`, '').replace(/,? according to$/, '').replace(/ from$| on$/, '')}
            </button>
          ))}
        </div>
        <div className="live-actions">
          <button className="btn primary lg" onClick={runBoth} disabled={!canRun}>
            <Icon name="send" size={15} /> Run with and without VAJRA <kbd>Ctrl</kbd><kbd>Enter</kbd>
          </button>
          {controls}
          <span className="muted runbar-model"><Icon name="cpu" size={13} /> {providerLabel}</span>
        </div>
      </section>

      <div className="panels">
        <RunPanel mode="unprotected" run={unprotected} scenario={scenario} disabled={!canRun} providerLabel={providerLabel}
          onRun={() => unprotected.start(params('unprotected'))} />
        <RunPanel mode="protected" run={protectedRun} scenario={scenario} disabled={!canRun} providerLabel={providerLabel}
          onRun={() => protectedRun.start(params('protected'))} />
      </div>
    </div>
  )
}
