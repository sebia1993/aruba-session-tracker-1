from __future__ import annotations

import ctypes
import gc
import json
import os
import sys
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aruba_session_tracker.models import DiagnosticEvent, QueryRequest, SessionObservation
from aruba_session_tracker.services.tracker import QueryOutcome, RawSnapshot
from aruba_session_tracker.storage import SessionStore


@dataclass(frozen=True, slots=True)
class ProcessUsage:
    handles: int
    threads: int
    working_set_bytes: int


def run_storage_soak(root: Path, polls: int) -> dict[str, object]:
    store = SessionStore(root / "tracker.db", root / "raw", root / "exports")
    store.initialize()
    run_id = store.start_run(
        QueryRequest("192.0.2.100", "203.0.113.80", 53000, 443),
        run_id="storage-soak-run",
        started_at=datetime(2026, 8, 28, 0, 0, tzinfo=UTC),
    )
    started = datetime(2026, 8, 28, 0, 0, tzinfo=UTC)
    expected_raw_bytes = 0
    expected_diagnostics = 0
    warmup_polls = min(100, polls)
    baseline_usage: ProcessUsage | None = None

    for index in range(polls):
        observed_at = started + timedelta(minutes=index)
        observation = SessionObservation(
            controller_name="MD-SOAK-01",
            controller_host="198.51.100.21",
            protocol=6,
            source_ip="192.0.2.100",
            destination_ip="203.0.113.80",
            source_port=53000,
            destination_port=443,
            counter="0/0",
            priority=0,
            tos=0,
            age=index % 60,
            destination="local",
            tunnel_age=index,
            packets=index,
            bytes_count=index * 128,
            flags="FC",
            cpu_id=index % 4,
            raw_line="fixture-only",
            observed_at=observed_at,
        )
        raw_output = f"fixture poll={index:06d} packets={index} bytes={index * 128}\n"
        expected_raw_bytes += len(raw_output.encode())
        diagnostics: tuple[DiagnosticEvent, ...] = ()
        if index % 100 == 0:
            diagnostics = (
                DiagnosticEvent(
                    stage="soak_fixture",
                    code=None,
                    message=f"fixture checkpoint {index}",
                    occurred_at=observed_at,
                ),
            )
            expected_diagnostics += 1
        poll_id = f"{index:032x}"
        persistence = store.record_poll_batch(
            run_id,
            QueryOutcome(
                observations=(observation,),
                diagnostics=diagnostics,
                raw_snapshots=(
                    RawSnapshot(
                        device_name="MD-SOAK-01",
                        command="show datapath session table 192.0.2.100",
                        output=raw_output,
                        observed_at=observed_at,
                        observation_keys=(observation.session_key,),
                    ),
                ),
                authoritative=True,
            ),
            poll_id=poll_id,
        )
        if persistence.poll_id != poll_id:
            raise AssertionError(f"unexpected poll receipt id at poll {index}")
        if index + 1 == warmup_polls:
            gc.collect()
            baseline_usage = windows_process_usage()

    store.finish_run(run_id, ended_at=started + timedelta(minutes=polls))
    gc.collect()
    final_usage = windows_process_usage()
    if baseline_usage is None:  # pragma: no cover - guarded by poll validation
        raise RuntimeError("resource baseline was not captured")
    return {
        "expected_raw_bytes": expected_raw_bytes,
        "expected_diagnostics": expected_diagnostics,
        "baseline": asdict(baseline_usage),
        "final": asdict(final_usage),
    }


def windows_process_usage() -> ProcessUsage:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    kernel32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    process = kernel32.GetCurrentProcess()
    handle_count = wintypes.DWORD()
    if not kernel32.GetProcessHandleCount(process, ctypes.byref(handle_count)):
        raise ctypes.WinError(ctypes.get_last_error())
    memory = ProcessMemoryCounters()
    memory.cb = ctypes.sizeof(memory)
    if not psapi.GetProcessMemoryInfo(process, ctypes.byref(memory), memory.cb):
        raise ctypes.WinError(ctypes.get_last_error())

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    thread_count = 0
    try:
        entry = ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            raise ctypes.WinError(ctypes.get_last_error())
        process_id = int(kernel32.GetCurrentProcessId())
        while True:
            if int(entry.th32OwnerProcessID) == process_id:
                thread_count += 1
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return ProcessUsage(
        handles=int(handle_count.value),
        threads=thread_count,
        working_set_bytes=int(memory.WorkingSetSize),
    )


if __name__ == "__main__":
    if os.name != "nt" or len(sys.argv) != 3:
        raise SystemExit(2)
    result = run_storage_soak(Path(sys.argv[1]), int(sys.argv[2]))
    print(json.dumps(result, sort_keys=True))
