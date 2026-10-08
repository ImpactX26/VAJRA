import { useEffect, useState } from 'react'
import { Icon } from './Icon.jsx'

// Status and controls for the Windows Sandbox VM that hosts the web-fetching MCP server.

export function useWinSandbox() {
  const [vm, setVm] = useState(null)
  const refresh = () => fetch('/api/winsandbox').then((r) => r.json()).then(setVm).catch(() => setVm(null))
  useEffect(() => {
    refresh()
  }, [])
  return [vm, setVm, refresh]
}

export function WinSandboxChip({ vm }) {
  if (!vm) return null
  return (
    <span className={`vm-chip ${vm.ready ? 'on' : ''}`}>
      <Icon name="monitor" size={13} />
      {vm.ready ? 'Fetching inside Windows Sandbox VM' : 'VM off: Job Object sandbox in use'}
    </span>
  )
}

function useElapsed(active) {
  const [s, setS] = useState(0)
  useEffect(() => {
    if (!active) return undefined
    setS(0)
    const id = setInterval(() => setS((x) => x + 1), 1000)
    return () => clearInterval(id)
  }, [active])
  return s
}

export function WinSandboxPanel() {
  const [vm, setVm, refresh] = useWinSandbox()
  const [busy, setBusy] = useState(null)
  const elapsed = useElapsed(busy === 'start')

  const call = async (action) => {
    setBusy(action)
    try {
      setVm(await (await fetch(`/api/winsandbox/${action}`, { method: 'POST' })).json())
    } finally {
      setBusy(null)
      refresh()
    }
  }

  const state = busy === 'start' ? 'booting' : busy === 'stop' ? 'stopping' : vm?.ready ? 'running' : vm?.installed === false ? 'missing' : 'off'
  const label = {
    booting: `Booting a fresh VM and starting the MCP server inside it (${elapsed}s)`,
    stopping: 'Stopping and wiping the VM',
    running: 'Running. Protected web fetches happen inside the VM.',
    missing: 'Windows Sandbox is not installed on this machine.',
    off: 'Off. Protected runs use the Windows Job Object sandbox.',
  }[state]

  return (
    <section className="box vm-panel">
      <div className="section-head">
        <div className="vm-title">
          <span className="feature-icon"><Icon name="monitor" size={18} /></span>
          <div>
            <h2 className="section-title">Windows Sandbox virtual machine</h2>
            <p className="muted">
              The web-fetching MCP server runs inside a disposable Windows VM. Pages are downloaded and opened there; VAJRA
              receives the result, checks it and removes what is unsafe. Stopping the VM wipes everything inside it.
            </p>
          </div>
        </div>
        {vm?.ready ? (
          <button className="btn" onClick={() => call('stop')} disabled={!!busy}><Icon name="stop" size={14} /> Stop VM</button>
        ) : (
          <button className="btn primary" onClick={() => call('start')} disabled={!!busy || vm?.installed === false}>
            <Icon name={busy === 'start' ? 'activity' : 'play'} size={14} /> {busy === 'start' ? 'Booting' : 'Start VM'}
          </button>
        )}
      </div>
      <div className={`vm-status st-${state}`} role="status">
        <span className="status-dot" />
        <span>{vm == null ? 'Checking status' : label}</span>
        {vm?.ready && <code className="vm-url">{vm.url}</code>}
      </div>
      {state === 'booting' && <div className="indeterminate" />}
    </section>
  )
}
