r"""Run the web-fetching MCP server inside Windows Sandbox (a disposable VM).

Uses the Windows Sandbox CLI (``wsb``):
  1. ``wsb start``  boots a VM headless with the folders below shared in;
  2. ``wsb exec``   runs start.ps1 inside it as SYSTEM, which starts the demo website and
                    the web MCP server (HTTP, port 8765) and opens that port in the VM firewall;
  3. ``wsb ip``     gives the VM's address; VAJRA connects to http://<ip>:8765/mcp;
  4. ``wsb stop``   destroys the VM and everything that happened inside it.

Shared into the VM read-only: demo/ (no secrets), the Python runtime, its standard
library and the installed packages. The only writable share is the handoff folder.
Folders containing a .env file (API keys) are never shared.
"""

from __future__ import annotations

import encodings
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HANDOFF = ROOT / ".sandbox-handoff"
STATE = HANDOFF / "sandbox.json"
MCP_PORT = 8765
NOTE = "Windows Sandbox (disposable VM, wiped on close)"


def _python_home() -> Path:
    """Folder with python.exe, read from the venv's pyvenv.cfg (sys.base_prefix is unreliable here)."""
    cfg = Path(sys.prefix) / "pyvenv.cfg"
    if cfg.exists():
        for line in cfg.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "home" and (Path(value.strip()) / "python.exe").exists():
                return Path(value.strip())
    return Path(getattr(sys, "_base_executable", sys.executable)).parent


PY_HOME = _python_home()
SITE_PACKAGES = Path(sys.prefix) / "Lib" / "site-packages"
# Folder holding Lib/ and DLLs/. On some installs it is separate from python.exe; os.__file__ is
# unreliable for frozen modules, encodings.__file__ is not.
STDLIB_HOME = Path(encodings.__file__).resolve().parents[2]

BOOT = r'''# Inside the VM: register the shared packages as a site dir (so .pth files such as pywin32's run),
# then run the target script with its arguments.
import runpy, site, sys
site.addsitedir(r"C:\vajra-pkgs")
target = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(target, run_name="__main__")
'''


class UnsafeShare(RuntimeError):
    pass


def _check_share(host: Path) -> None:
    """Never share secrets into the VM: refuse a folder that holds a .env file or contains the project."""
    if (host / ".env").exists() or (host not in (ROOT / "demo", HANDOFF) and ROOT.is_relative_to(host)):
        raise UnsafeShare(f"refusing to share {host} into Windows Sandbox")
    if host == ROOT / "demo" and any(host.rglob(".env")):
        raise UnsafeShare(f"refusing to share {host}: it contains a .env file")


def _wsb() -> str | None:
    found = subprocess.run(["where", "wsb"], capture_output=True, text=True).stdout.strip().splitlines()
    return found[0] if found else None


def available() -> bool:
    return sys.platform == "win32" and _wsb() is not None


def _start_script() -> str:
    py = PY_HOME / "python.exe"
    return rf"""$ErrorActionPreference = 'Continue'
$env:PYTHONHOME = 'C:\vajra-pyhome'
$env:PYTHONDONTWRITEBYTECODE = '1'
$log = 'C:\handoff\sandbox.log'
"booting $(Get-Date -Format o)" | Out-File $log
netsh advfirewall firewall add rule name=vajra-mcp dir=in action=allow protocol=TCP localport={MCP_PORT} | Out-File $log -Append
Start-Process -FilePath '{py}' -ArgumentList 'C:\handoff\boot.py','C:\vajra\demo\backend\site_server.py','--port','8090' `
  -WindowStyle Hidden -RedirectStandardError 'C:\handoff\site.err'
Start-Process -FilePath '{py}' -ArgumentList 'C:\handoff\boot.py','C:\vajra\demo\backend\mock_servers.py','--role','web','--transport','http','--host','0.0.0.0','--port','{MCP_PORT}' `
  -WindowStyle Hidden -RedirectStandardError 'C:\handoff\mcp.err'
for ($i = 0; $i -lt 120; $i++) {{
  if (Get-NetTCPConnection -LocalPort {MCP_PORT} -State Listen -ErrorAction SilentlyContinue) {{ "listening" | Out-File $log -Append; break }}
  Start-Sleep -Milliseconds 500
}}
"""


def _config() -> str:
    def folder(host: Path, inside: str, ro: bool) -> str:
        _check_share(host)
        return (
            f"<MappedFolder><HostFolder>{host}</HostFolder><SandboxFolder>{inside}</SandboxFolder>"
            f"<ReadOnly>{'true' if ro else 'false'}</ReadOnly></MappedFolder>"
        )

    folders = "".join([
        folder(ROOT / "demo", r"C:\vajra\demo", True),
        folder(PY_HOME, str(PY_HOME), True),
        folder(SITE_PACKAGES, r"C:\vajra-pkgs", True),
        folder(STDLIB_HOME, r"C:\vajra-pyhome", True),
        folder(HANDOFF, r"C:\handoff", False),
    ])
    return (
        "<Configuration><Networking>Enable</Networking><ClipboardRedirection>Disable</ClipboardRedirection>"
        "<PrinterRedirection>Disable</PrinterRedirection><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>"
        f"<MemoryInMB>2048</MemoryInMB><MappedFolders>{folders}</MappedFolders></Configuration>"
    )


def _wsb_json(*args: str, timeout: int = 300) -> dict:
    out = subprocess.run([_wsb(), *args, "--raw"], capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(out.stdout or "{}")
    except ValueError:
        return {"error": (out.stdout + out.stderr).strip()[:400]}


def launch() -> dict:
    """Boot a VM, start the servers inside it, and record how to reach them. Blocks ~1-3 minutes."""
    if not available():
        return {"ok": False, "error": "Windows Sandbox (wsb) is not available"}
    HANDOFF.mkdir(parents=True, exist_ok=True)
    for stale in ("sandbox.json", "sandbox.log", "mcp.err", "site.err"):
        try:
            (HANDOFF / stale).unlink(missing_ok=True)
        except OSError:
            pass
    (HANDOFF / "start.ps1").write_text(_start_script(), encoding="utf-8")
    (HANDOFF / "boot.py").write_text(BOOT, encoding="utf-8")

    started = _wsb_json("start", "--config", _config())
    vm = started.get("Id")
    if not vm:
        return {"ok": False, "error": f"wsb start failed: {started}"}
    ran = _wsb_json("exec", "--id", vm, "-c",
                    r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\handoff\start.ps1", "-r", "System")
    nets = _wsb_json("ip", "--id", vm).get("Networks") or [{}]
    ip = nets[0].get("IpV4Address")
    STATE.write_text(json.dumps({"id": vm, "ip": ip, "port": MCP_PORT}), encoding="utf-8")
    info = state()
    info["exec"] = ran
    return {"ok": info["ready"], **info}


def stop() -> dict:
    data = _read_state()
    if data.get("id"):
        _wsb_json("stop", "--id", data["id"], timeout=120)
    STATE.unlink(missing_ok=True)
    return {"ok": True}


def _read_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}


def state() -> dict:
    """Is a VM up and its MCP server reachable from the host?"""
    info = {"installed": available(), "ready": False, "url": None, "id": None, "note": NOTE}
    data = _read_state()
    if data.get("ip"):
        info["id"] = data.get("id")
        info["url"] = f"http://{data['ip']}:{data['port']}/mcp"
        info["ready"] = _reachable(info["url"])
    for name in ("sandbox.log", "mcp.err"):
        path = HANDOFF / name
        if path.exists():
            info[name.replace(".", "_")] = path.read_text(encoding="utf-8", errors="replace").replace("\x00", "")[-500:]
    return info


def _reachable(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError:
        return True  # the MCP endpoint answered (it rejects a plain GET), so the server is up
    except OSError:
        return False
    return True
