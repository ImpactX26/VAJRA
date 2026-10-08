import { Icon } from './Icon.jsx'

// Animated overview: outside content flows into VAJRA, is checked and sealed, and only
// permitted actions come out the other side. Pure SVG + SMIL, no libraries.

const SOURCES = [
  { y: 50, icon: 'file', label: 'Files' },
  { y: 130, icon: 'globe', label: 'Web' },
  { y: 210, icon: 'mail', label: 'Email' },
]

export function FlowHero() {
  return (
    <svg className="flow-hero" viewBox="0 0 720 260" role="img" aria-label="Data flowing through VAJRA">
      <defs>
        <linearGradient id="fh-shield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#1d4ed8" />
          <stop offset="1" stopColor="#0f766e" />
        </linearGradient>
        <filter id="fh-shadow" x="-50%" y="-50%" width="200%" height="200%">
          <feDropShadow dx="0" dy="6" stdDeviation="8" floodColor="#0f172a" floodOpacity="0.18" />
        </filter>
        {SOURCES.map((s, i) => (
          <path key={i} id={`fh-in-${i}`} d={`M126,${s.y} C220,${s.y} 250,130 326,130`} />
        ))}
        <path id="fh-out" d="M414,130 L556,130" />
        <path id="fh-act" d="M614,130 C640,130 640,70 690,70" />
      </defs>

      {SOURCES.map((s, i) => (
        <g key={s.label}>
          <use href={`#fh-in-${i}`} className="fh-wire" />
          <rect x="20" y={s.y - 24} width="106" height="48" rx="10" className="fh-node" />
          <Icon name={s.icon} x={36} y={s.y - 9} size={18} className="fh-icon" />
          <text x="62" y={s.y + 5} className="fh-label">{s.label}</text>
          {[0, 1].map((k) => (
            <circle key={k} r="5" className="fh-packet raw">
              <animateMotion dur="3s" begin={`-${i * 0.7 + k * 1.5}s`} repeatCount="indefinite">
                <mpath href={`#fh-in-${i}`} />
              </animateMotion>
            </circle>
          ))}
        </g>
      ))}

      <g filter="url(#fh-shadow)">
        <path d="M370,74 L414,91 L414,138 C414,170 393,188 370,198 C347,188 326,170 326,138 L326,91 Z" fill="url(#fh-shield)" />
      </g>
      <text x="370" y="140" className="fh-shield-text">VAJRA</text>
      <text x="370" y="224" className="fh-caption">label · sanitize · seal · enforce</text>

      <use href="#fh-out" className="fh-wire safe" />
      {[0, 1, 2].map((k) => (
        <g key={k}>
          <rect width="14" height="10" x="-7" y="-5" rx="2" className="fh-sealed" />
          <animateMotion dur="2.4s" begin={`-${k * 0.8}s`} repeatCount="indefinite">
            <mpath href="#fh-out" />
          </animateMotion>
        </g>
      ))}

      <rect x="556" y="106" width="58" height="48" rx="10" className="fh-node ai" />
      <Icon name="cpu" x={573} y={118} size={24} className="fh-icon ai" />
      <text x="585" y="176" className="fh-caption">Model sees sealed references</text>

      <use href="#fh-act" className="fh-wire safe" />
      <circle r="5" className="fh-packet ok">
        <animateMotion dur="2s" repeatCount="indefinite"><mpath href="#fh-act" /></animateMotion>
      </circle>
      <text x="652" y="52" className="fh-caption">Permitted actions</text>
    </svg>
  )
}
