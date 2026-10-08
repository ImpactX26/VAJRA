import { useState } from 'react'
import { Doc } from '../highlight.jsx'
import { GUIDE, LAYERS, STATUS } from '../injectionGuide.js'

function Intro() {
  return (
    <section className="ia-intro">
      <div>
        <h2>What is indirect prompt injection?</h2>
        <p>
          An LLM agent reads its instructions and its data through the <b>same channel</b>: the context window.
          When a tool returns a file, a web page or an email, any text in it that <i>looks</i> like an instruction
          competes with the user’s real request. The attacker never talks to the agent directly. They plant text
          where the agent will read it.
        </p>
      </div>
      <div className="ia-principle">
        <h2>VAJRA’s principle</h2>
        <p>
          Don’t try to recognise malicious text. That’s a classifier arms race. Instead, separate data by
          <b> where it came from</b>: untrusted bytes never reach the model that can act, and code, not a model,
          decides which data may flow into which tool argument.
        </p>
      </div>
    </section>
  )
}

function LayerRow({ index, layer, step }) {
  const st = STATUS[step.status]
  return (
    <li className={`ia-layer status-${step.status}`}>
      <div className="ia-layer-num">{index + 1}</div>
      <div className="ia-layer-main">
        <div className="ia-layer-head">
          <h4>{layer.name}</h4>
          <span className={`ia-status status-${step.status}`}>{st.icon} {st.label}</span>
        </div>
        <p className="ia-layer-what muted">{layer.what}</p>
        <div className="ia-payload">
          <span className="ia-payload-label">Payload after this layer</span>
          <code>{step.payload}</code>
        </div>
        <p className="ia-layer-text">{step.text}</p>
        <code className="ia-code">{layer.code}</code>
      </div>
    </li>
  )
}

function Matrix({ scenarios, onPick, current }) {
  return (
    <section className="ia-card">
      <h3>All demo attacks × all layers</h3>
      <p className="muted">Where each attack is processed, contained and stopped. Click a row to open it.</p>
      <div className="ia-matrix-wrap">
        <table className="ia-matrix">
          <thead>
            <tr>
              <th>Attack</th>
              {LAYERS.map((l, i) => <th key={l.id} className={l.planned ? 'planned' : ''}>{i + 1}. {l.short}</th>)}
            </tr>
          </thead>
          <tbody>
            {scenarios.map((s) => (
              <tr key={s.id} className={s.id === current ? 'current' : ''} onClick={() => onPick(s.id)}>
                <td className="ia-matrix-name">{s.title}</td>
                {LAYERS.map((l) => {
                  const step = GUIDE[s.id].layers[l.id]
                  return (
                    <td key={l.id} className={`status-${step.status}`} title={STATUS[step.status].label}>
                      {STATUS[step.status].icon}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="ia-legend">
        {Object.entries(STATUS).map(([k, v]) => <span key={k} className={`ia-status status-${k}`}>{v.icon} {v.label}</span>)}
      </div>
    </section>
  )
}

export function InjectionsPage({ scenarios, onRunLive }) {
  const [current, setCurrent] = useState(scenarios[0].id)
  const scenario = scenarios.find((s) => s.id === current)
  const guide = GUIDE[current]
  const payload = scenario.file_contents[0]

  return (
    <div className="ia">
      <Intro />

      <div className="scenarios">
        {scenarios.map((s, i) => (
          <button key={s.id} className={`scenario ${s.id === current ? 'selected' : ''}`} onClick={() => setCurrent(s.id)}>
            <span className="scenario-num">Injection {i + 1}</span>
            <span className="scenario-title">{s.title}</span>
            <span className="scenario-attack">{s.attack}</span>
          </button>
        ))}
      </div>

      <section className="ia-card ia-overview">
        <div>
          <h2>{scenario.title}</h2>
          <p className="attack-type">{guide.family}</p>
          <p>{scenario.summary}</p>
          <div className="ia-tags">{guide.techniques.map((t) => <span key={t} className="ia-tag">{t}</span>)}</div>
        </div>
        <dl className="ia-facts">
          <dt>Planted in</dt><dd><code>{payload.path}</code></dd>
          <dt>Enters the agent via</dt><dd><code>{guide.entry}</code></dd>
          <dt>Attacker’s goal</dt><dd>{guide.target}</dd>
          <dt>User’s actual task</dt><dd>“{scenario.task}”</dd>
          <dd className="ia-run"><button className="run-both" onClick={() => onRunLive(current)}>▶ Run this attack live</button></dd>
        </dl>
      </section>

      <section className="ia-two">
        <div className="ia-card">
          <h3>📄 The payload (the actual demo file)</h3>
          <p className="muted">Red lines are the injection. This is exactly what the MCP server returns to whoever calls it.</p>
          <div className="ia-payload-doc"><Doc text={payload.content} scenario={scenario} /></div>
        </div>
        <div className="ia-card">
          <h3>🔬 Anatomy: how it manipulates the model</h3>
          <ol className="ia-anatomy">
            {guide.anatomy.map((a, i) => (
              <li key={i}>
                <code className="ia-quote">{a.quote}</code>
                <span className="ia-tag danger">{a.technique}</span>
                <p>{a.why}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="ia-two">
        <div className="ia-card ia-without">
          <h3>⚠️ Without VAJRA: how the attack succeeds</h3>
          <ol className="ia-steps">{guide.withoutVajra.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </div>
        <div className="ia-card ia-with">
          <h3>🛡️ With VAJRA: outcome</h3>
          <p className="ia-verdict">{guide.verdict}</p>
          <p className="muted">
            The trace below follows this payload through each VAJRA layer, in the order a tool result is processed.
            Layers 8–9 are on the roadmap and shown for completeness.
          </p>
        </div>
      </section>

      <section className="ia-card">
        <h3>🧅 Layer by layer: what VAJRA does to this injection</h3>
        <ol className="ia-layers">
          {LAYERS.map((layer, i) => <LayerRow key={layer.id} index={i} layer={layer} step={guide.layers[layer.id]} />)}
        </ol>
      </section>

      <Matrix scenarios={scenarios} current={current} onPick={setCurrent} />
    </div>
  )
}
