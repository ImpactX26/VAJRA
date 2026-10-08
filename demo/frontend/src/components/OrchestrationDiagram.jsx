import { containsInjection, hasHandle } from '../highlight.jsx'

// Live map of the MCP orchestration. The latest event lights up the hop it
// describes; accumulated events set persistent node states (hijacked, blocked…).

const NODES = {
  user: { x: 8, y: 125, w: 96, h: 50, label: 'User', sub: 'Alice' },
  planner: { x: 134, y: 125, w: 118, h: 50, label: 'Planner LLM', sub: 'calls tools' },
  store: { x: 300, y: 58, w: 150, h: 44, label: 'Taint store', sub: 'labels · handles' },
  policy: { x: 300, y: 128, w: 150, h: 44, label: 'Policy engine', sub: 'deterministic code' },
  reader: { x: 300, y: 198, w: 150, h: 44, label: 'Quarantine LLM', sub: 'zero tools' },
  files: { x: 500, y: 30, w: 116, h: 50, label: 'files', sub: 'MCP server' },
  web: { x: 500, y: 125, w: 116, h: 50, label: 'web', sub: 'MCP server' },
  mail: { x: 500, y: 220, w: 116, h: 50, label: 'mail', sub: 'MCP server' },
}
const PROXY = { x: 286, y: 18, w: 178, h: 264 }
const SERVERS = ['files', 'web', 'mail']

const right = (n) => [NODES[n].x + NODES[n].w, NODES[n].y + NODES[n].h / 2]
const left = (n) => [NODES[n].x, NODES[n].y + NODES[n].h / 2]
const line = ([x1, y1], [x2, y2]) => `M${x1},${y1} L${x2},${y2}`
const curve = ([x1, y1], [x2, y2]) => `M${x1},${y1} C${x1 + 120},${y1} ${x2 - 120},${y2} ${x2},${y2}`

function edgesFor(mode) {
  const edges = { 'user-planner': line(right('user'), left('planner')) }
  if (mode === 'protected') {
    edges['planner-proxy'] = line(right('planner'), [PROXY.x, 150])
    for (const s of SERVERS) edges[`proxy-${s}`] = line([PROXY.x + PROXY.w, left(s)[1]], left(s))
    edges['policy-reader'] = line([375, 172], [375, 198])
    edges['policy-store'] = line([375, 128], [375, 102])
  } else {
    for (const s of SERVERS) edges[`planner-${s}`] = curve(right('planner'), left(s))
  }
  return edges
}

const serverOf = (tool = '') => {
  const s = tool.split(/__|\//)[0]
  return s === 'vajra' ? 'reader' : s
}

/** Which hop does this event describe? → { edges: [[id, dir, tone]], nodes: {id: tone} } */
function flowFor(ev, mode, scenario) {
  const P = mode === 'protected'
  const out = { edges: [], nodes: {} }
  if (!ev) return out
  const srv = serverOf(ev.tool)
  switch (ev.type) {
    case 'run.start':
    case 'llm.tools':
      out.edges.push(['user-planner', 'fwd', 'info'])
      out.nodes.user = 'info'
      break
    case 'llm.request':
    case 'llm.response':
      out.nodes.planner = ev.tool_calls?.some((c) => containsInjection(c.arguments, scenario)) ? 'danger' : 'info'
      break
    case 'mcp.call':
      if (P) out.edges.push(['planner-proxy', 'fwd', 'info'])
      else out.edges.push([`planner-${srv}`, 'fwd', containsInjection(JSON.stringify(ev.arguments), scenario) ? 'danger' : 'info'])
      out.nodes[P ? 'policy' : srv] = 'info'
      break
    case 'proxy.resolve':
      out.nodes.policy = 'info'
      if (ev.handles?.length) out.edges.push(['policy-store', 'fwd', 'info'])
      break
    case 'proxy.block':
      out.edges.push(['planner-proxy', 'fwd', 'danger'])
      out.nodes.policy = 'blocked'
      break
    case 'proxy.allow':
      out.nodes.policy = 'safe'
      if (srv === 'reader') out.edges.push(['policy-reader', 'fwd', 'info'])
      else out.edges.push([`proxy-${srv}`, 'fwd', 'info'])
      out.nodes[srv] = 'info'
      break
    case 'proxy.label':
      if (srv === 'reader') out.edges.push(['policy-reader', 'rev', ev.trusted ? 'safe' : 'danger'])
      else out.edges.push([`proxy-${srv}`, 'rev', ev.trusted ? 'safe' : 'danger'])
      out.nodes.store = 'info'
      break
    case 'proxy.withhold':
      out.nodes.store = 'safe'
      break
    case 'quarantine.input':
    case 'quarantine.output':
      out.nodes.reader = 'info'
      break
    case 'mcp.result': {
      const bad = containsInjection(ev.text, scenario)
      if (P) out.edges.push(['planner-proxy', 'rev', bad ? 'danger' : 'safe'])
      else out.edges.push([`planner-${srv}`, 'rev', bad ? 'danger' : 'info'])
      out.nodes.planner = bad ? 'danger' : 'info'
      break
    }
    case 'agent.final':
      out.edges.push(['user-planner', 'rev', 'info'])
      out.nodes.user = 'info'
      break
    case 'outbox':
      out.nodes.mail = 'info'
      break
    default:
  }
  return out
}

function persistentState(events, mode, scenario) {
  const badges = {}
  const tones = {}
  const sawInjection = events.some((e) => e.type === 'mcp.result' && containsInjection(e.text, scenario))
  if (sawInjection) {
    tones.planner = 'danger'
    badges.planner = 'hijacked by injection'
  } else if (mode === 'protected' && events.some((e) => e.type === 'mcp.result' && hasHandle(e.text))) {
    badges.planner = 'sees handles only'
  }
  const blocks = events.filter((e) => e.type === 'proxy.block').length
  if (blocks) {
    tones.policy = 'blocked'
    badges.policy = `${blocks} blocked`
  }
  const withheld = events.filter((e) => e.type === 'proxy.withhold').length
  if (withheld) badges.store = `${withheld} withheld`
  if (events.some((e) => e.type === 'quarantine.output')) badges.reader = 'output stays tainted'
  const verdict = events.find((e) => e.type === 'verdict')
  if (verdict?.status === 'compromised') {
    tones.mail = 'danger'
    badges.mail = 'data exfiltrated'
  } else if (verdict) {
    tones.mail = 'safe'
    badges.mail = verdict.status === 'safe' ? `only ${scenario.user_name.split(" ")[0]}` : 'nothing sent'
  }
  return { tones, badges }
}

function Node({ id, tone, badge, dim, sub }) {
  const n = NODES[id]
  return (
    <g className={`node ${tone ? `tone-${tone}` : ''} ${dim ? 'dim' : ''}`}>
      <rect x={n.x} y={n.y} width={n.w} height={n.h} rx="9" />
      <text x={n.x + n.w / 2} y={n.y + 20} className="node-label">{n.label}</text>
      <text x={n.x + n.w / 2} y={n.y + 36} className="node-sub">{sub ?? n.sub}</text>
      {badge && <text x={n.x + n.w / 2} y={n.y + n.h + 14} className={`node-badge ${tone ? `tone-${tone}` : ''}`}>{badge}</text>}
    </g>
  )
}

export function OrchestrationDiagram({ mode, events, scenario, providerLabel }) {
  const P = mode === 'protected'
  const edges = edgesFor(mode)
  const last = events[events.length - 1]
  const flow = flowFor(last, mode, scenario)
  const { tones, badges } = persistentState(events, mode, scenario)
  const active = Object.fromEntries(flow.edges.map(([id, dir, tone]) => [id, { dir, tone }]))
  const nodeTone = (id) => flow.nodes[id] || tones[id]

  return (
    <svg className="diagram" viewBox="0 0 624 300" role="img" aria-label="MCP orchestration diagram">
      <g className={`proxy ${P ? '' : 'absent'}`}>
        <rect x={PROXY.x} y={PROXY.y} width={PROXY.w} height={PROXY.h} rx="14" />
        <text x={PROXY.x + PROXY.w / 2} y={PROXY.y + 26} className="proxy-label">
          {P ? 'VAJRA proxy' : 'no security layer'}
        </text>
      </g>
      {Object.entries(edges).map(([id, d]) => {
        const a = active[id]
        return <path key={id} d={d} className={`edge ${a ? `on tone-${a.tone} ${a.dir}` : ''}`} />
      })}
      <Node id="user" tone={nodeTone('user')} sub={scenario.user_name.split(" ")[0]} />
      <Node id="planner" tone={nodeTone('planner')} badge={badges.planner} />
      {P && ['store', 'policy', 'reader'].map((id) => <Node key={id} id={id} tone={nodeTone(id)} badge={badges[id]} />)}
      {SERVERS.map((id) => <Node key={id} id={id} tone={nodeTone(id)} badge={badges[id]} />)}
      <text x="193" y="118" className="node-sub">{providerLabel}</text>
    </svg>
  )
}
