import { useState } from 'react'

// Interactive walk-through of VAJRA's rules, run in the browser.
// Mirrors the real engine: trust comes from the SOURCE (never the words),
// untrusted data is sealed behind a handle, and per-argument policy decides.

const SOURCES = {
  user: { label: '👤 Typed by the user', trusted: true },
  file: { label: '📄 A file the assistant opened', trusted: false },
  web: { label: '🌐 A web page', trusted: false },
  email: { label: '✉️ An email someone sent', trusted: false },
}

const DESTINATIONS = {
  body: { label: 'The text of an email', arg: 'send_email.body', acceptsOutside: true },
  to: { label: 'Who an email is sent to', arg: 'send_email.to', acceptsOutside: false },
  subject: { label: 'An email’s subject line', arg: 'send_email.subject', acceptsOutside: false },
  path: { label: 'Which file to open next', arg: 'read_file.path', acceptsOutside: false },
}

const randomHandle = () =>
  '$vajra:h_' + Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('')

export function Playground() {
  const [text, setText] = useState('Quarterly report attached. Totals are on page 3.')
  const [source, setSource] = useState('file')
  const [dest, setDest] = useState('body')
  const [result, setResult] = useState(null)

  const run = () => {
    const trusted = SOURCES[source].trusted
    const d = DESTINATIONS[dest]
    setResult({
      key: Date.now(),
      trusted,
      handle: trusted ? null : randomHandle(),
      allowed: trusted || d.acceptsOutside,
      d,
      text,
    })
  }

  return (
    <div className="playground">
      <div className="pg-inputs">
        <label className="pg-field">
          <span>1 · Any text</span>
          <textarea value={text} onChange={(e) => { setText(e.target.value); setResult(null) }} rows={4} />
          <small className="muted">The words don’t matter to VAJRA. Try anything.</small>
        </label>
        <label className="pg-field">
          <span>2 · Where did it come from?</span>
          <div className="pg-chips">
            {Object.entries(SOURCES).map(([k, v]) => (
              <button key={k} className={`chip-btn ${source === k ? 'on' : ''}`} onClick={() => { setSource(k); setResult(null) }}>
                {v.label}
              </button>
            ))}
          </div>
        </label>
        <label className="pg-field">
          <span>3 · Where should it go?</span>
          <div className="pg-chips">
            {Object.entries(DESTINATIONS).map(([k, v]) => (
              <button key={k} className={`chip-btn ${dest === k ? 'on' : ''}`} onClick={() => { setDest(k); setResult(null) }}>
                {v.label}
              </button>
            ))}
          </div>
        </label>
        <button className="btn primary big" onClick={run}>⚡ Send it through VAJRA</button>
      </div>

      <div className="pg-steps">
        {!result && <div className="pg-empty">Choose the options on the left and press the button to see each check.</div>}
        {result && (
          <ol key={result.key} className="pg-flow">
            <li className={`pg-step ${result.trusted ? 'ok' : 'warn'}`} style={{ animationDelay: '0s' }}>
              <b>Check 1 · Label</b>
              <p>
                Source: {SOURCES[source].label}. Labelled{' '}
                <span className={`tag ${result.trusted ? 'trusted' : 'untrusted'}`}>{result.trusted ? 'TRUSTED' : 'UNTRUSTED'}</span>.
                The text itself was not inspected.
              </p>
            </li>
            <li className={`pg-step ${result.trusted ? 'ok' : 'seal'}`} style={{ animationDelay: '0.6s' }}>
              <b>Check 2 · What the AI sees</b>
              {result.trusted ? (
                <p>Trusted, so the AI sees it as written: <q>{result.text}</q></p>
              ) : (
                <p>
                  Sealed. The AI only receives <code className="mark-handle">{result.handle}</code>. The original text stays inside
                  VAJRA.
                </p>
              )}
            </li>
            <li className={`pg-step ${result.allowed ? 'ok' : 'stop'}`} style={{ animationDelay: '1.2s' }}>
              <b>Check 3 · Policy for <code>{result.d.arg}</code></b>
              {result.allowed ? (
                <p>✅ Allowed. {result.trusted ? 'Trusted data may go anywhere.' : 'This field accepts outside data.'}</p>
              ) : (
                <p>⛔ Blocked. <code>{result.d.arg}</code> only accepts data from the user. Nothing is executed; the user is asked to confirm.</p>
              )}
            </li>
          </ol>
        )}
      </div>
    </div>
  )
}
