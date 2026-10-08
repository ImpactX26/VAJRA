import { useEffect, useRef } from 'react'
import { Icon } from './Icon.jsx'
import { Doc, containsInjection, hasHandle } from '../highlight.jsx'

const HIDDEN = new Set(['llm.request', 'outbox', 'verdict', 'vajra.report'])

const short = (v) => {
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > 140 ? `${s.slice(0, 140)}…` : s
}

function Args({ args, scenario }) {
  const entries = Object.entries(args || {})
  if (!entries.length) return <code className="args">()</code>
  return (
    <Doc
      className="args"
      scenario={scenario}
      text={entries.map(([k, v]) => `${k} = ${short(v)}`).join('\n')}
    />
  )
}

function parseArgs(raw) {
  try {
    return JSON.parse(raw || '{}')
  } catch {
    return { raw }
  }
}

/** Turns one backend event into a timeline card (or null to skip). */
function describe(ev, scenario, mode) {
  const P = mode === 'protected'
  switch (ev.type) {
    case 'run.start':
      return {
        actor: 'user', icon: 'user', title: 'User request',
        body: <><p className="quote">“{ev.task}”</p><p className="muted">Planner model: {ev.provider}</p></>,
      }
    case 'mcp.connected':
      return {
        actor: 'mcp', icon: 'server', title: `${P ? 'VAJRA' : 'Agent'} connected to ${Object.keys(ev.servers).length} MCP servers`,
        body: <ul className="plain">{Object.entries(ev.servers).map(([s, t]) => <li key={s}><b>{s}</b>: {t.join(', ')}</li>)}</ul>,
      }
    case 'llm.tools':
      return {
        actor: 'planner', icon: 'tool', title: 'Planner is given its tool list',
        body: <p className="muted">{ev.tools.join(' · ')}</p>,
      }
    case 'llm.response': {
      const calls = ev.tool_calls || []
      if (!calls.length) return null // the answer itself is shown by the agent.final card
      const hijacked = calls.some((c) => containsInjection(c.arguments, scenario) || /secrets\//.test(c.arguments))
      return {
        actor: 'planner', icon: 'cpu', tone: hijacked ? 'danger' : undefined,
        title: `Planner decides: ${calls.map((c) => c.name).join(', ')}`,
        body: (
          <>
            {ev.content && <p className="thought">{ev.content.length > 400 ? `${ev.content.slice(0, 400)}…` : ev.content}</p>}
            {calls.map((c, i) => <Args key={i} args={parseArgs(c.arguments)} scenario={scenario} />)}
            {hijacked && <p className="flag danger">This action was dictated by the injected text, not by the user.</p>}
          </>
        ),
      }
    }
    case 'mcp.call':
      return {
        actor: P ? 'vajra' : 'mcp', icon: 'send',
        title: P ? `tools/call ${ev.tool} → VAJRA proxy` : `tools/call ${ev.tool} → ${ev.tool.split('__')[0]} MCP server (direct)`,
        body: <Args args={ev.arguments} scenario={scenario} />,
      }
    case 'proxy.resolve':
      return {
        actor: 'vajra', icon: 'tag', title: 'Taint check: label every argument',
        body: (
          <>
            <div className="chips">
              {Object.entries(ev.arg_labels).map(([k, l]) => <span key={k} className={`chip ${l}`}>{k}: {l}</span>)}
              {!Object.keys(ev.arg_labels).length && <span className="muted">no arguments</span>}
            </div>
            {ev.handles?.length > 0 && <p className="muted">Handles resolved proxy-side: {ev.handles.map((h) => <code key={h} className="mark-handle">{h}</code>)}</p>}
          </>
        ),
      }
    case 'proxy.block':
      return {
        actor: 'vajra', icon: 'ban', tone: 'blocked', title: 'BLOCKED by deterministic policy',
        body: <><p>{ev.reason}</p><p className="muted">No model was asked. A label check in code refused the call before it reached the mail server.</p></>,
      }
    case 'proxy.allow':
      return {
        actor: 'vajra', icon: 'check-circle', tone: 'safe',
        title: ev.tool === 'vajra/quarantine' ? 'Policy OK → handing data to the quarantined reader' : `Policy OK → forwarded to ${ev.tool.split('/')[0]} MCP server`,
      }
    case 'proxy.label':
      return {
        actor: 'vajra', icon: ev.trusted ? 'check-circle' : 'alert', tone: ev.trusted ? undefined : 'warn',
        title: `Output labelled ${ev.trusted ? 'TRUSTED' : 'UNTRUSTED'}`,
        body: (
          <>
            <p className="muted">{ev.label}</p>
            <p className="caption">Raw upstream output, held inside VAJRA (the planner never sees this):</p>
            <Doc text={ev.preview} scenario={scenario} maxLines={24} />
          </>
        ),
      }
    case 'proxy.withhold':
      return {
        actor: 'vajra', icon: 'lock', tone: 'safe', title: 'Withheld: the planner only gets an opaque handle',
        body: <p><code className="mark-handle">{ev.handle}</code> <span className="muted">({ev.chars} chars stay in the taint store)</span></p>,
      }
    case 'proxy.pass':
      return { actor: 'vajra', icon: 'arrow-right', title: 'Trusted output passed through' }
    case 'proxy.taint_context':
      return { actor: 'vajra', icon: 'alert', tone: 'danger', title: 'Planner context is now tainted', body: <p>{ev.label}</p> }
    case 'quarantine.input':
      return {
        actor: 'reader', icon: 'flask', title: 'Quarantined reader LLM invoked (it has no tools)',
        body: (
          <>
            <Doc text={ev.prompt} scenario={scenario} maxLines={18} />
            {containsInjection(ev.prompt, scenario) && (
              <p className="flag safe">The reader can see the injection, but it has no tools. Whatever it writes stays tainted data.</p>
            )}
          </>
        ),
      }
    case 'quarantine.output':
      return {
        actor: 'reader', icon: 'package', title: 'Reader output → stored as a new tainted handle',
        body: <Doc text={ev.text} scenario={scenario} maxLines={12} />,
      }
    case 'mcp.result': {
      const bad = containsInjection(ev.text, scenario)
      const handle = hasHandle(ev.text)
      return {
        actor: 'planner', icon: 'eye', tone: bad ? 'danger' : ev.is_error ? 'blocked' : handle ? 'safe' : undefined,
        title: `What the planner LLM sees (${ev.tool})`,
        body: (
          <>
            <Doc text={ev.text} scenario={scenario} maxLines={24} />
            {bad && <p className="flag danger">Attacker-controlled content entered the LLM's context.</p>}
            {!bad && handle && <p className="flag safe">Only an opaque handle. No injected text reached the LLM.</p>}
          </>
        ),
      }
    }
    case 'llm.rate_limited':
      return { actor: 'planner', icon: 'clock', title: `Groq free-tier rate limit: waiting ${ev.seconds}s` }
    case 'agent.final':
      return { actor: 'planner', icon: 'message', title: 'Planner reply to the user', body: <p className="thought">{ev.text}</p> }
    case 'error':
      return { actor: 'system', icon: 'alert', tone: 'danger', title: 'Error', body: <p>{ev.message}</p> }
    default:
      return null
  }
}

const ACTORS = { user: 'User', planner: 'Planner LLM', vajra: 'VAJRA', mcp: 'MCP', reader: 'Quarantine LLM', system: 'System' }

export function Timeline({ events, scenario, mode }) {
  const list = useRef(null)
  useEffect(() => {
    const el = list.current
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' })
  }, [events.length])

  const cards = events.filter((e) => !HIDDEN.has(e.type)).map((ev, i) => [ev, describe(ev, scenario, mode), i])
  return (
    <ol className="timeline" ref={list}>
      {cards.map(([ev, c, i]) =>
        c ? (
          <li key={i} className={`card actor-${c.actor} ${c.tone ? `tone-${c.tone}` : ''}`}>
            <div className="card-head">
              <span className="tl-icon"><Icon name={c.icon} size={14} /></span>
              <span className="actor">{ACTORS[c.actor]}</span>
              <span className="title">{c.title}</span>
              <span className="time">{ev.t?.toFixed(1)}s</span>
            </div>
            {c.body && <div className="card-body">{c.body}</div>}
          </li>
        ) : null,
      )}
    </ol>
  )
}
