import { useEffect, useState } from 'react'

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
      🖥️ {vm.ready ? 'Web pages are fetched inside a Windows Sandbox VM' : 'Windows Sandbox VM is off: using the Job Object sandbox'}
    </span>
  )
}

export function WinSandboxPanel() {
  const [vm, setVm, refresh] = useWinSandbox()
  const [busy, setBusy] = useState(null)

  const call = async (action) => {
    setBusy(action)
    try {
      setVm(await (await fetch(`/api/winsandbox/${action}`, { method: 'POST' })).json())
    } finally {
      setBusy(null)
      refresh()
    }
  }

  return (
    <section className="box vm-panel">
      <div className="proof-head">
        <div>
          <h2 className="section-title">🖥️ Windows Sandbox (virtual machine)</h2>
          <p className="muted">
            The strongest isolation: the web-fetching MCP server runs inside a disposable Windows VM. Pages are downloaded
            and opened there; VAJRA receives the result, checks it and burns what is unsafe. Closing the VM wipes everything.
          </p>
        </div>
        <div className="vm-actions">
          {vm?.ready ? (
            <button className="btn" onClick={() => call('stop')} disabled={!!busy}>{busy === 'stop' ? 'Stopping…' : '⏹ Stop VM'}</button>
          ) : (
            <button className="btn primary" onClick={() => call('start')} disabled={!!busy || vm?.installed === false}>
              {busy === 'start' ? 'Booting VM… (1-3 min)' : '▶ Start the VM'}
            </button>
          )}
        </div>
      </div>
      <div className={`vm-status ${vm?.ready ? 'on' : ''}`}>
        <span className={`dot ${vm?.ready ? 'up' : 'down'}`} />
        {vm == null && 'Checking…'}
        {vm && !vm.installed && 'Windows Sandbox is not installed on this machine.'}
        {vm && vm.installed && !vm.ready && !busy && 'VM is off. Protected runs use the Windows Job Object sandbox.'}
        {busy === 'start' && 'Booting a fresh VM and starting the MCP server inside it…'}
        {vm?.ready && <>VM running · MCP server at <code>{vm.url}</code> · protected web fetches happen inside it</>}
      </div>
    </section>
  )
}
