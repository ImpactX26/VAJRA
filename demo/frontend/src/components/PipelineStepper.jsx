import { useState } from 'react'
import { Icon } from './Icon.jsx'

// Live progress through the request pipeline, derived from the run's event stream.

const PROTECTED = [
  { id: 'request', label: 'Request', icon: 'user', help: 'The user asks the assistant to do something.' },
  { id: 'token', label: 'Token', icon: 'key', help: 'VAJRA reads the user’s own request and issues signed capability tokens, e.g. send email only to the address the user typed.' },
  { id: 'isolate', label: 'Isolate', icon: 'monitor', help: 'Tool servers start inside an OS sandbox (Job Object or Windows Sandbox VM).' },
  { id: 'fetch', label: 'Fetch', icon: 'globe', help: 'The tool runs inside the sandbox and returns its raw output to VAJRA.' },
  { id: 'sanitize', label: 'Sanitize', icon: 'flame', help: 'Everything a person could not see (hidden elements, comments, invisible characters) is burned.' },
  { id: 'seal', label: 'Seal', icon: 'lock', help: 'The output is labelled untrusted and replaced by a sealed reference. The AI never sees the text.' },
  { id: 'reader', label: 'Reader', icon: 'flask', help: 'A separate AI with no tools reads the sealed content and produces a summary, which stays untrusted.' },
  { id: 'grammar', label: 'Grammar', icon: 'tool', help: 'Every action must be a well-formed call to an approved tool. Free text can never become an action.' },
  { id: 'policy', label: 'Policy', icon: 'shield-check', help: 'Fixed rules and capability tokens decide which data may flow into which action. Unsafe actions are blocked.' },
  { id: 'deliver', label: 'Deliver', icon: 'inbox', help: 'The safe result reaches the user.' },
]

const UNPROTECTED = [
  { id: 'request', label: 'Request', icon: 'user', help: 'The user asks the assistant to do something.' },
  { id: 'fetch', label: 'Fetch', icon: 'globe', help: 'The tool runs directly, with no isolation.' },
  { id: 'read', label: 'AI reads raw', icon: 'eye', help: 'The raw content, including any hidden instructions, goes straight into the AI.' },
  { id: 'act', label: 'Act', icon: 'send', help: 'The AI takes actions based on everything it read.' },
  { id: 'deliver', label: 'Result', icon: 'inbox', help: 'Whatever the AI produced is returned.' },
]

function progress(events, mode) {
  const reached = new Set()
  let blocked = false
  for (const e of events) {
    const t = e.type
    if (t === 'run.start') reached.add('request')
    if (t === 'capability.mint') reached.add('token')
    if (t === 'proxy.grammar') reached.add('grammar')
    if (t === 'sandbox.isolation') reached.add('isolate')
    if (t === 'mcp.call' && !e.tool.endsWith('send_email') && e.tool !== 'vajra__quarantine') reached.add('fetch')
    if (t === 'mcp.result' && mode === 'unprotected') reached.add('read')
    if (t === 'proxy.sanitize') reached.add('sanitize')
    if (t === 'proxy.withhold' && !e.tool.startsWith('vajra/') && !e.tool.startsWith('mail/')) reached.add('seal')
    if (t === 'quarantine.input' || t === 'quarantine.output') reached.add('reader')
    if (t === 'proxy.allow' && e.tool === 'mail/send_email') reached.add('policy')
    if (t === 'proxy.block') {
      reached.add('grammar')
      reached.add('policy')
      blocked = true
    }
    if (t === 'mcp.call' && e.tool.endsWith('send_email') && mode === 'unprotected') reached.add('act')
    if (t === 'vajra.deliver' || t === 'agent.final') {
      if (mode === 'protected') reached.add('policy')
      reached.add('deliver')
      if (mode === 'unprotected') reached.add('act')
    }
  }
  return { reached, blocked }
}

export function PipelineStepper({ events, mode, phase }) {
  const stages = mode === 'protected' ? PROTECTED : UNPROTECTED
  const { reached, blocked } = progress(events, mode)
  const lastIdx = Math.max(-1, ...stages.map((s, i) => (reached.has(s.id) ? i : -1)))
  const finished = phase === 'done' || events.some((e) => e.type === 'verdict')
  const [focus, setFocus] = useState(null)

  const statusOf = (s, i) => {
    if (s.id === 'policy' && blocked) return 'blocked'
    if (reached.has(s.id)) return i === lastIdx && !finished ? 'active' : 'done'
    if (finished || i < lastIdx) return 'skipped'
    return 'pending'
  }
  const pct = stages.length > 1 ? Math.max(0, lastIdx) / (stages.length - 1) : 0
  const shown = focus ?? stages[Math.max(0, lastIdx)]

  return (
    <div className={`stepper ${mode}`}>
      <div className="stepper-track">
        <div className="stepper-fill" style={{ width: `${pct * 100}%` }} />
      </div>
      <ol className="stepper-list">
        {stages.map((s, i) => {
          const st = statusOf(s, i)
          return (
            <li key={s.id} className={`step st-${st}`}>
              <button
                type="button"
                className="step-dot"
                aria-label={`${s.label}: ${st}`}
                onMouseEnter={() => setFocus(s)}
                onMouseLeave={() => setFocus(null)}
                onFocus={() => setFocus(s)}
                onBlur={() => setFocus(null)}
              >
                <Icon name={st === 'blocked' ? 'ban' : st === 'done' ? 'check' : s.icon} size={14} />
              </button>
              <span className="step-label">{s.label}</span>
            </li>
          )
        })}
      </ol>
      {events.length > 0 && shown && (
        <p className="stepper-help">
          <b>{shown.label}.</b> {shown.help}
        </p>
      )}
    </div>
  )
}
