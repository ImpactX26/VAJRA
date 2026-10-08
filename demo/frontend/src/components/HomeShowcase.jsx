import { useEffect, useState } from 'react'
import { href } from '../router.js'
import { FlowHero } from './FlowHero.jsx'
import { Icon } from './Icon.jsx'

// Home page: dark hero with a live system-status panel, the flow diagram, measured results,
// a spotlight on the newest features, the feature map and a short guided tour.

const FEATURES = [
  { icon: 'target', tone: 'red', title: 'Attacks', text: 'Four injection scenarios, run side by side with and without VAJRA.', link: href.attacks },
  { icon: 'shield-check', tone: 'blue', title: 'Threats', text: 'Five threats, the rule that stops each, and a live self-test.', link: '#/threats', isNew: true },
  { icon: 'file', tone: 'green', title: 'Secure convert', text: 'Image to PDF and PDF merge with the real iLovePDF. Unsafe files are burned.', link: '#/convert', isNew: true },
  { icon: 'package', tone: 'amber', title: 'Sandbox', text: 'Tool admission checks, OS isolation and the Windows Sandbox VM.', link: '#/sandbox' },
  { icon: 'activity', tone: 'violet', title: 'Monitor', text: 'Live audit trail, alerts and continuous integrity scanning.', link: '#/monitor' },
  { icon: 'layers', tone: 'indigo', title: 'How it works', text: 'The layers every tool result passes through, in order.', link: href.how },
  { icon: 'search', tone: 'slate', title: 'Attack anatomy', text: 'Each payload and the layer that stops it.', link: href.anatomy() },
  { icon: 'chart', tone: 'cyan', title: 'Results', text: 'Measured runs with a live model and a worst-case model.', link: href.results },
]

const PRINCIPLES = ['No AI classifiers', 'Deterministic policy', 'OS-level sandbox', 'Tamper-evident audit']

function useJson(url) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let live = true
    fetch(url).then((r) => (r.ok ? r.json() : null)).then((d) => live && setData(d)).catch(() => live && setData(false))
    return () => { live = false }
  }, [url])
  return data
}

function StatusRow({ icon, label, value, state }) {
  return (
    <li className={`hs-row ${state}`}>
      <span className="hs-row-icon"><Icon name={icon} size={15} /></span>
      <span className="hs-row-label">{label}</span>
      <span className="hs-row-value">
        {state === 'wait' ? <span className="hs-skel" /> : value}
      </span>
    </li>
  )
}

function LiveStatus() {
  const test = useJson('/api/selftest?quiet=1')
  const chain = useJson('/api/audit/verify')
  const conv = useJson('/api/convert/status')
  const state = (d, ok) => (d === null ? 'wait' : d && ok(d) ? 'ok' : 'warn')
  return (
    <aside className="hs-status" aria-label="Live system status">
      <div className="hs-status-head">
        <span className="hs-pulse" /> Live system status
      </div>
      <ul>
        <StatusRow icon="shield-check" label="Threat self-test" state={state(test, (d) => d.ok)}
          value={test ? `${test.passed}/${test.total} passing` : 'unavailable'} />
        <StatusRow icon="lock" label="Audit chain" state={state(chain, (d) => d.ok)}
          value={chain ? (chain.ok ? `verified, ${chain.records ?? chain.count ?? 'all'} records` : 'broken') : 'unavailable'} />
        <StatusRow icon="globe" label="iLovePDF" state={state(conv, (d) => d.ilovepdf)}
          value={conv ? (conv.ilovepdf ? 'connected' : 'key missing') : 'unavailable'} />
        <StatusRow icon="cpu" label="Planner model" state="ok" value="gpt-oss-120b" />
      </ul>
      <a className="hs-status-link" href="#/threats">Open the self-test <Icon name="arrow-right" size={13} /></a>
    </aside>
  )
}

function ConvertArt() {
  return (
    <svg className="sp-art" viewBox="0 0 320 120" role="img" aria-label="File goes through the sandbox and is delivered or burned">
      <defs>
        <linearGradient id="spg" x1="0" x2="1"><stop offset="0" stopColor="#2563eb" /><stop offset="1" stopColor="#0d9488" /></linearGradient>
      </defs>
      <path d="M40 60 H140" className="sp-line" />
      <path d="M180 60 C 220 60, 230 28, 270 28" className="sp-line ok" />
      <path d="M180 60 C 220 60, 230 92, 270 92" className="sp-line bad" />
      <circle r="4" className="sp-dot"><animateMotion dur="2.4s" repeatCount="indefinite" path="M40 60 H140" /></circle>
      <rect x="14" y="40" width="34" height="40" rx="5" className="sp-file" />
      <path d="M22 52 h18 M22 60 h18 M22 68 h12" className="sp-file-lines" />
      <path d="M160 34 l22 8 v16 c0 14 -10 22 -22 28 c-12 -6 -22 -14 -22 -28 v-16 z" fill="url(#spg)" />
      <path d="m151 60 6 6 12 -12" className="sp-check" />
      <circle cx="284" cy="28" r="15" className="sp-ok" />
      <path d="m277 28 5 5 9 -9" className="sp-check" />
      <circle cx="284" cy="92" r="15" className="sp-bad" />
      <path d="M284 84 c5 5 6 8 6 11 a6 6 0 1 1 -12 0 c0 -3 2 -5 3 -6 c0 2 1 3 2 3 c0 -3 -1 -5 1 -8z" className="sp-flame" />
    </svg>
  )
}

function ThreatArt() {
  const rows = ['Indirect injection', 'Tool poisoning', 'Shadowing and lateral', 'Data exfiltration', 'Command and SQL injection']
  return (
    <ul className="sp-threats">
      {rows.map((r, i) => (
        <li key={r} style={{ animationDelay: `${i * 0.12}s` }}>
          <span className="sp-num">{String(i + 1).padStart(2, '0')}</span>
          <span>{r}</span>
          <Icon name="check-circle" size={15} />
        </li>
      ))}
    </ul>
  )
}

export function HomeShowcase({ bench, without, withV, CountUp }) {
  return (
    <div className="page home2">
      <section className="hs-band">
        <div className="hs-grid-bg" aria-hidden="true" />
        <div className="hs-inner">
          <div className="hs-copy">
            <span className="hs-eyebrow"><span className="hs-eyebrow-dot" /> Zero-trust MCP proxy</span>
            <h1>
              Security for AI agents that holds even when the model is <span className="hs-accent">fooled</span>
            </h1>
            <p>
              VAJRA sits between an AI assistant and its tools. Every result is labelled, sealed and checked by fixed
              rules before the assistant can act on it, so a hidden instruction cannot take control.
            </p>
            <div className="hs-cta">
              <a className="btn hs-primary lg" href={href.attacks}><Icon name="play" size={15} /> Watch the demos</a>
              <a className="btn hs-outline lg" href="#/convert"><Icon name="file" size={15} /> Try Secure convert</a>
            </div>
            <ul className="hs-principles">
              {PRINCIPLES.map((p) => <li key={p}><Icon name="check" size={13} /> {p}</li>)}
            </ul>
          </div>
          <LiveStatus />
        </div>
      </section>

      <section className="box hero-visual hs-lift">
        <FlowHero />
      </section>

      {bench && (
        <a className="hs-metrics" href={href.results}>
          <div className="hs-metric">
            <span className="hs-metric-value bad"><CountUp value={without.hit} />/{without.total}</span>
            <span className="hs-metric-label">runs hijacked without VAJRA</span>
          </div>
          <div className="hs-metric">
            <span className="hs-metric-value good"><CountUp value={withV.hit} />/{withV.total}</span>
            <span className="hs-metric-label">runs hijacked with VAJRA</span>
          </div>
          <div className="hs-metric">
            <span className="hs-metric-value blue"><CountUp value={5} />/5</span>
            <span className="hs-metric-label">threat classes defended</span>
          </div>
          <div className="hs-metric-note">
            AgentDojo benchmark payload (ETH Zurich) against a live model, {bench.meta.model}.
            <span className="link-inline">View all results <Icon name="arrow-right" size={14} /></span>
          </div>
        </a>
      )}

      <section className="hs-section">
        <div className="hs-section-head">
          <span className="eyebrow">New in this version</span>
          <h2>Built for real tools and real files</h2>
        </div>
        <div className="sp-grid">
          <a className="sp-card green" href="#/convert">
            <div className="sp-top">
              <span className="sp-tag">New</span>
              <span className="sp-kicker">Real third-party tool</span>
            </div>
            <h3>Secure convert with iLovePDF</h3>
            <p>Turn photos into a PDF or merge PDFs with the real iLovePDF service. VAJRA checks your files before they
              leave and the result before it reaches your device. Anything unsafe is burned in the sandbox.</p>
            <ConvertArt />
            <span className="sp-go">Open Secure convert <Icon name="arrow-right" size={14} /></span>
          </a>
          <a className="sp-card blue" href="#/threats">
            <div className="sp-top">
              <span className="sp-tag">New</span>
              <span className="sp-kicker">Live self-test</span>
            </div>
            <h3>Five threats, five fixed rules</h3>
            <p>Every major attack on AI tool use, mapped to the rule that stops it. The checks run against the real
              policy code each time the page opens.</p>
            <ThreatArt />
            <span className="sp-go">Open Threat coverage <Icon name="arrow-right" size={14} /></span>
          </a>
        </div>
      </section>

      <section className="hs-section">
        <div className="hs-section-head">
          <span className="eyebrow">Explore</span>
          <h2>Everything VAJRA does, one page each</h2>
        </div>
        <div className="hf-grid">
          {FEATURES.map((f) => (
            <a key={f.title} className={`hf-card ${f.tone}`} href={f.link}>
              <span className="hf-icon"><Icon name={f.icon} size={19} /></span>
              <span className="hf-title">{f.title}{f.isNew && <span className="hf-new">New</span>}</span>
              <span className="hf-text">{f.text}</span>
              <span className="hf-go"><Icon name="arrow-right" size={15} /></span>
            </a>
          ))}
        </div>
      </section>

      <section className="hs-tour">
        <div className="hs-tour-head">
          <h2>See it work in one minute</h2>
          <p>Demo files are in <code>demo/convert_samples</code>.</p>
        </div>
        <ol>
          <li><span>1</span><div><strong>Convert a clean photo</strong><small>Upload the safe receipt and download the PDF.</small></div></li>
          <li><span>2</span><div><strong>Try an unsafe file</strong><small>Merge with the script PDF. It burns before upload.</small></div></li>
          <li><span>3</span><div><strong>Check the evidence</strong><small>Every decision is in the Monitor audit trail.</small></div></li>
        </ol>
        <a className="btn hs-primary lg" href="#/convert">Start <Icon name="arrow-right" size={15} /></a>
      </section>
    </div>
  )
}
