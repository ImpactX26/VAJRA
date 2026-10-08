import { Doc } from '../highlight.jsx'
import { GUIDE, LAYERS, STATUS } from '../injectionGuide.js'
import { href } from '../router.js'
import { Icon } from './Icon.jsx'
import { SourceEvidence } from './Panels.jsx'

// Minimal anatomy: the payload on one side, VAJRA's layers as one line each on
// the other. The layer that stops the attack is highlighted and expanded.

export function InjectionsPage({ scenarios, currentId }) {
  const current = scenarios.some((s) => s.id === currentId) ? currentId : scenarios[0].id
  const scenario = scenarios.find((s) => s.id === current)
  const guide = GUIDE[current]
  const payload = scenario.file_contents[0]

  return (
    <div className="page">
      <header className="page-header"><span className="eyebrow">Deep dive</span><h1 className="page-title">Attack anatomy</h1></header>
      <nav className="an-tabs">
        {scenarios.map((s, i) => (
          <a key={s.id} href={href.anatomy(s.id)} className={s.id === current ? 'on' : ''}>
            {i + 1} · {s.title}
          </a>
        ))}
      </nav>

      <section className="box an-head">
        <div>
          <h2>{scenario.title}</h2>
          <p className="attack-type">{guide.family}</p>
          <div className="ia-tags">{guide.techniques.map((t) => <span key={t} className="ia-tag">{t}</span>)}</div>
        </div>
        <a className="btn primary" href={href.demo(current)}><Icon name="play" size={14} /> Run demo</a>
      </section>

      <section className="an-body">
        <div className="box">
          <h3><Icon name="file" size={15} /> The payload</h3>
          <p className="muted an-sub">{payload.path}. Red lines are the injection.</p>
          <div className="an-doc"><Doc text={payload.content} scenario={scenario} /></div>
          <SourceEvidence source={scenario.source} />
        </div>

        <div className="box">
          <h3><Icon name="shield" size={15} /> How VAJRA handles it</h3>
          <ol className="an-steps">
            {LAYERS.map((l) => {
              const step = guide.layers[l.id]
              const st = STATUS[step.status]
              return (
                <li key={l.id} className={`an-step status-${step.status}`}>
                  <details open={step.status === 'stop'}>
                    <summary>
                      <span className="an-name">{l.name}</span>
                      <span className={`ia-status status-${step.status}`}><Icon name={st.icon} size={12} /> {st.label}</span>
                    </summary>
                    <p>{step.text}</p>
                  </details>
                </li>
              )
            })}
          </ol>
          <p className="an-verdict">{guide.verdict}</p>
        </div>
      </section>
    </div>
  )
}
