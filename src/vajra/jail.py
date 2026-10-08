"""Run a command inside an operating-system sandbox. Standalone: no VAJRA imports,
so it can be launched by file path in a server's stripped environment.

    python jail.py --memory-mb 256 --cpu-seconds 60 --max-processes 3 -- <command> [args...]

Windows: the jailer puts itself in a Job Object, then starts the server, which
inherits the job. Enforced by the OS kernel:
  * per-process memory cap         (JOB_OBJECT_LIMIT_PROCESS_MEMORY)
  * per-process CPU-time cap        (JOB_OBJECT_LIMIT_PROCESS_TIME)
  * no extra processes beyond the limit (JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
  * everything killed when the jailer exits (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
POSIX: the same limits through setrlimit (RLIMIT_AS, RLIMIT_CPU, RLIMIT_NPROC).

stdin/stdout are inherited, so MCP's stdio transport works unchanged.
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def _windows_job(memory_mb: int, cpu_seconds: int, max_processes: int) -> None:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.AssignProcessToJobObject.restype = wintypes.BOOL

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    PROCESS_TIME, ACTIVE_PROCESS, PROCESS_MEMORY, DIE_ON_EXCEPTION, KILL_ON_CLOSE = 0x2, 0x8, 0x100, 0x400, 0x2000
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = PROCESS_TIME | ACTIVE_PROCESS | PROCESS_MEMORY | DIE_ON_EXCEPTION | KILL_ON_CLOSE
    info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_seconds * 10_000_000  # 100 ns units
    info.BasicLimitInformation.ActiveProcessLimit = max_processes
    info.ProcessMemoryLimit = memory_mb * 1024 * 1024

    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
    if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):  # 9 = ExtendedLimitInformation
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    # The handle stays open for the jailer's lifetime; closing it on exit kills the whole job.
    _windows_job.handle = job  # type: ignore[attr-defined]


def _posix_limits(memory_mb: int, cpu_seconds: int, max_processes: int):
    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds,) * 2)
        resource.setrlimit(resource.RLIMIT_NPROC, (max_processes,) * 2)

    return apply


def main() -> int:
    parser = argparse.ArgumentParser(prog="jail")
    parser.add_argument("--memory-mb", type=int, default=256)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    parser.add_argument("--max-processes", type=int, default=3)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        parser.error("missing command")

    preexec = None
    if sys.platform == "win32":
        _windows_job(args.memory_mb, args.cpu_seconds, args.max_processes)
    else:
        preexec = _posix_limits(args.memory_mb, args.cpu_seconds, args.max_processes)
    return subprocess.call(cmd, preexec_fn=preexec)  # inherits stdin/stdout for MCP stdio


if __name__ == "__main__":
    sys.exit(main())
