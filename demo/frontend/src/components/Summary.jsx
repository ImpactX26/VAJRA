import { containsInjection } from '../highlight.jsx'
import { Icon } from './Icon.jsx'

// A short, plain-English recap of one run, built from its event stream.
// Each line is one thing that happened; repeats are merged ("×3").

function args(raw) {
  if (typeof raw !== 'string') return raw || {}
  try {
    return JSON.parse(raw || '{}')
  } catch {
    return {}
  }
}

function lookedAt(tool, a) {
  if (tool.endsWith('read_file')) return { icon: 'file', text: `Opened “${a.path}”.` }
  if (tool.endsWith('list_files')) return { icon: 'folder', text: 'Listed the files.' }
  if (tool.endsWith('fetch_url')) return { icon: 'globe', text: `Opened a web page (${a.url}).` }
  if (tool === 'vajra__quarantine') {
    return { icon: 'flask', tone: 'safe', text: 'Sent the sealed content to VAJRA’s reader, an AI with no abilities, to summarise.' }
  }
  return { icon: 'tool', text: `Used the tool ${tool}.` }
}

export function buildSummary(events, mode, scenario) {
  const lines = []
  const add = (line) => {
    const last = lines[lines.length - 1]
    if (last && last.text === line.text) last.count += 1
    else lines.push({ count: 1, ...line })
  }
  const attackers = new Set(scenario.attacker_addresses.map((x) => x.toLowerCase()))
  const mailLine = (to) =>
    attackers.has(to.toLowerCase())
      ? { icon: 'mail', tone: 'danger', text: `Emailed ${to}, an address that came from the file, not from the user.` }
      : to.toLowerCase() === scenario.user_email
      ? { icon: 'mail', tone: 'ok', text: `Emailed the result to ${scenario.user_name} (${to}).` }
      : { icon: 'mail', text: `Emailed ${to}.` }

  let pendingMail = null
  let sawInjection = false
  for (const ev of events) {
    switch (ev.type) {
      case 'run.start':
        add({ icon: 'user', text: `${scenario.user_name} asked the assistant for help.` })
        break
      case 'mcp.call': {
        const a = args(ev.arguments)
        if (ev.tool.endsWith('send_email')) {
          if (mode === 'protected') pendingMail = a
          else add(mailLine(a.to || ''))
        } else {
          add(lookedAt(ev.tool, a))
        }
        break
      }
      case 'mcp.result':
        if (mode === 'unprotected' && !sawInjection && containsInjection(ev.text, scenario)) {
          sawInjection = true
          add({ icon: 'alert', tone: 'danger', text: 'The hidden text in that content went straight into the AI’s view.' })
        }
        break
      case 'capability.mint': {
        if (!ev.gated || !ev.gated.length) break
        const tok = (ev.tokens || []).find((t) => t.tool === 'mail/send_email')
        add(tok
          ? { icon: 'key', tone: 'safe', text: `VAJRA issued a signed token from ${scenario.user_name}'s own request: email may go only to ${tok.bindings.to.join(', ')}.` }
          : { icon: 'key', tone: 'safe', text: `The request named no recipient, so VAJRA issued no email token: no address is authorised.` })
        break
      }
      case 'proxy.capability':
        add({ icon: 'key', tone: 'safe', text: 'The recipient matched the token from the user’s request.' })
        break
      case 'sandbox.isolation': {
        const kinds = [...new Set(Object.values(ev.servers))].filter((k) => k !== 'no isolation')
        if (kinds.length) add({ icon: 'lock', tone: 'safe', text: `The tool servers ran inside an OS sandbox: ${kinds.join('; ')}.` })
        break
      }
      case 'proxy.sanitize':
        if (ev.burned.length) {
          add({ icon: 'flame', tone: 'safe', text: `VAJRA's sandbox burned ${ev.burned.length} hidden part${ev.burned.length > 1 ? 's' : ''} of the content: things a person could not see.` })
        }
        break
      case 'vajra.deliver':
        add({ icon: 'inbox', tone: 'ok', text: 'VAJRA delivered the cleaned answer to the user.' })
        break
      case 'proxy.withhold':
        if (!ev.tool.startsWith('vajra/') && !ev.tool.startsWith('mail/')) {
          add({ icon: 'lock', tone: 'safe', text: 'VAJRA sealed that content. The AI only got a reference to it, never the text.' })
        }
        break
      case 'proxy.allow':
        if (ev.tool === 'mail/send_email' && pendingMail) {
          add(mailLine(pendingMail.to || ''))
          pendingMail = null
        }
        break
      case 'proxy.block': {
        const names = { grammar: 'action grammar', policy: 'data-flow policy', capability: 'capability token' }
        const by = Object.entries(ev.layers || {}).filter(([, why]) => why).map(([k]) => names[k] || k)
        add({ icon: 'ban', tone: 'blocked', text: `VAJRA blocked an email whose recipient came from outside content. Nothing was sent.${by.length > 1 ? ` Refused independently by ${by.length} layers: ${by.join(' and ')}.` : ''}` })
        pendingMail = null
        break
      }
      case 'agent.final': {
        const t = (ev.text || '').replace(/\s+/g, ' ').trim()
        add({ icon: 'message', text: `The assistant replied: “${t.length > 160 ? `${t.slice(0, 160)}…` : t}”` })
        break
      }
      case 'error':
        add({ icon: 'alert', tone: 'danger', text: `The run failed: ${ev.message}` })
        break
      default:
    }
  }
  return lines
}

export function Summary({ events, mode, scenario }) {
  const lines = buildSummary(events, mode, scenario)
  if (!lines.length) return null
  return (
    <ol className="summary">
      {lines.map((l, i) => (
        <li key={i} className={l.tone ? `tone-${l.tone}` : ''}>
          <span className="s-icon"><Icon name={l.icon} size={15} /></span>
          <span>
            {l.text}
            {l.count > 1 && <span className="s-count"> ×{l.count}</span>}
          </span>
        </li>
      ))}
    </ol>
  )
}
