// Visual marking of injected text, attacker addresses, opaque handles and leaked secrets.

export const HANDLE_RE = /\$vajra:h_[0-9a-f]{32}/
const SECRET_RE = /(?:sk-live-[\w-]+|AKIA\w+|FAKEdemoSecretKey[\w/]*|FAKE-hunter2)/

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export function containsInjection(text, scenario) {
  if (!text || !scenario) return false
  return [...scenario.injections, ...scenario.attacker_addresses].some((m) => text.includes(m))
}

export function hasHandle(text) {
  return HANDLE_RE.test(text || '')
}

function inlineMarks(line, scenario, key) {
  const parts = [HANDLE_RE.source, SECRET_RE.source, ...(scenario?.attacker_addresses || []).map(escape)]
  const re = new RegExp(`(${parts.join('|')})`, 'g')
  return line.split(re).map((chunk, i) => {
    if (!chunk) return null
    if (new RegExp(`^${HANDLE_RE.source}$`).test(chunk)) return <span key={`${key}-${i}`} className="mark-handle">{chunk}</span>
    if (new RegExp(`^${SECRET_RE.source}$`).test(chunk)) return <span key={`${key}-${i}`} className="mark-secret">{chunk}</span>
    if (scenario?.attacker_addresses?.includes(chunk)) return <span key={`${key}-${i}`} className="mark-attacker">{chunk}</span>
    return chunk
  })
}

/** Renders text line by line; lines carrying the injected payload are flagged. */
export function Doc({ text, scenario, maxLines, className = '' }) {
  let lines = (text ?? '').split('\n')
  const truncated = maxLines && lines.length > maxLines
  if (truncated) lines = lines.slice(0, maxLines)
  const markers = scenario?.injections || []
  return (
    <pre className={`doc ${className}`}>
      {lines.map((line, i) => {
        const injected = markers.some((m) => line.includes(m))
        return (
          <div key={i} className={injected ? 'line line-inj' : 'line'}>
            {line === '' ? ' ' : inlineMarks(line, scenario, i)}
          </div>
        )
      })}
      {truncated && <div className="line muted">…</div>}
    </pre>
  )
}
