// Animated overview: outside content flows into VAJRA, gets sealed, and only
// permitted actions come out the other side. Pure SVG + SMIL, no libraries.

const SOURCES = [
  { y: 50, icon: '📄', label: 'Files' },
  { y: 130, icon: '🌐', label: 'Web' },
  { y: 210, icon: '✉️', label: 'Email' },
]

export function FlowHero() {
  return (
    <svg className="flow-hero" viewBox="0 0 720 260" role="img" aria-label="Data flowing through VAJRA">
      <defs>
        <linearGradient id="fh-shield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#10b981" />
        </linearGradient>
        <filter id="fh-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="6" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        {SOURCES.map((s, i) => (
          <path key={i} id={`fh-in-${i}`} d={`M120,${s.y} C220,${s.y} 250,130 330,130`} />
        ))}
        <path id="fh-out" d="M410,130 L560,130" />
        <path id="fh-act" d="M610,130 C640,130 640,70 690,70" />
      </defs>

      {SOURCES.map((s, i) => (
        <g key={s.label}>
          <use href={`#fh-in-${i}`} className="fh-wire" />
          <rect x="20" y={s.y - 24} width="100" height="48" rx="12" className="fh-node" />
          <text x="34" y={s.y + 7} className="fh-emoji">{s.icon}</text>
          <text x="64" y={s.y + 5} className="fh-label">{s.label}</text>
          {[0, 1].map((k) => (
            <circle key={k} r="6" className="fh-packet raw">
              <animateMotion dur="3s" begin={`${i * 0.7 + k * 1.5}s`} repeatCount="indefinite">
                <mpath href={`#fh-in-${i}`} />
              </animateMotion>
            </circle>
          ))}
        </g>
      ))}

      <g filter="url(#fh-glow)">
        <path d="M370,78 L412,94 L412,138 C412,168 392,186 370,196 C348,186 328,168 328,138 L328,94 Z" fill="url(#fh-shield)" />
      </g>
      <text x="370" y="138" className="fh-shield-text">VAJRA</text>
      <text x="370" y="222" className="fh-caption">labels · seals · checks</text>

      <use href="#fh-out" className="fh-wire safe" />
      {[0, 1, 2].map((k) => (
        <g key={k}>
          <rect width="16" height="12" x="-8" y="-6" rx="3" className="fh-sealed" />
          <animateMotion dur="2.4s" begin={`${k * 0.8}s`} repeatCount="indefinite">
            <mpath href="#fh-out" />
          </animateMotion>
        </g>
      ))}

      <rect x="560" y="106" width="50" height="48" rx="12" className="fh-node ai" />
      <text x="585" y="137" className="fh-emoji center">🤖</text>
      <text x="585" y="176" className="fh-caption">AI sees only sealed refs</text>

      <use href="#fh-act" className="fh-wire safe" />
      <circle r="6" className="fh-packet ok">
        <animateMotion dur="2s" repeatCount="indefinite"><mpath href="#fh-act" /></animateMotion>
      </circle>
      <text x="655" y="52" className="fh-caption">✓ allowed actions</text>
    </svg>
  )
}
