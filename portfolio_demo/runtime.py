"""Session-local TrackerService / MonitorEngine orchestration, no database."""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import csv
import io
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aruba_session_tracker.models import Credentials, QueryRequest
from aruba_session_tracker.services.tracker import TrackerService, TrackerCallbacks
from aruba_session_tracker.services.monitoring import MonitorEngine
from aruba_session_tracker.storage.html_report import RunReportSnapshot, render_html_report
from portfolio_demo.fixture_transport import CONFIG, FixtureFactory, STAGES


class DemoRuntime:
    def __init__(self):
        self.factory = FixtureFactory()
        self.trace = []
        self.service = TrackerService(
            CONFIG, self.factory, TrackerCallbacks(progress=self._progress)
        )
        self.monitor = None
        self.request = None
        self.outcome = None
        self.result = None
        self.running = False
        self.poll_count = 0
        self.run_id = ""
        self.history = []
        self.observations = []
        self.events = []
        self.latest_lifecycle = {}
        self.virtual_time = time.monotonic()
        self.started = ""
        self.stage = "대기"

    def _progress(self, stage, device):
        self.trace.append({"Stage": stage, "Device": device})

    def start(self, request, monitor=False, mode="timeline"):
        if self.running:
            self.stop()
        self.request = request
        self.run_id = str(uuid4())
        self.started = datetime.now(timezone.utc).isoformat()
        self.poll_count = 0
        self.observations, self.events, self.latest_lifecycle = [], [], {}
        self.factory.tick = 0
        self.running = monitor
        self.result = None
        # These are synthetic protocol placeholders; no credential UI or real factory.
        credentials = Credentials("demo-not-an-account", "synthetic-not-a-secret")
        self.monitor = (
            MonitorEngine(
                self.service, request, credentials, monotonic_clock=lambda: self.virtual_time
            )
            if monitor
            else None
        )
        return self.poll(mode=mode)

    def poll(self, mode="timeline"):
        if self.request is None:
            raise ValueError("먼저 조회 조건을 입력하세요.")
        if self.poll_count >= 50:
            self.stop()
            raise ValueError("50 Poll 한도입니다. 새 조회 또는 Demo Reset을 사용하세요.")
        self.trace = []
        self.factory.trace = []
        self.factory.mode = mode
        self.factory.tick = min(self.poll_count, len(STAGES) - 1)
        self.stage = STAGES[self.factory.tick] if mode == "timeline" else mode
        # Advance an injected monotonic clock; never wait or start a daemon.
        self.virtual_time += CONFIG.session_interval_seconds
        if self.monitor:
            self.result = self.monitor.poll_once()
            self.outcome = self.result.outcome
            for event in self.result.events:
                row = {
                    "event_type": event.event_type.value,
                    "session_key": event.observation.session_key,
                    "occurred_at": event.occurred_at.isoformat(),
                    "instance_id": event.instance_id,
                    "miss_count": event.miss_count,
                }
                self.events.append(row)
                self.latest_lifecycle[event.instance_id] = event.event_type.value
        else:
            self.outcome = self.service.query_once(
                self.request,
                Credentials("demo-not-an-account", "synthetic-not-a-secret"),
                allow_full_scan=False,
            )
        self.poll_count += 1
        for observation in self.outcome.observations:
            self.observations.append(
                {
                    **asdict(observation),
                    "observed_at": observation.observed_at.isoformat(),
                    "session_key": observation.session_key,
                }
            )
        status = (
            "COMPLETED"
            if self.outcome.authoritative
            else ("PARTIAL" if self.outcome.observations else "FAILED")
        )
        row = {
            "Run ID": self.run_id,
            "Query": str(asdict(self.request)),
            "Started": self.started,
            "Polls": self.poll_count,
            "Status": status,
            "Session Count": len(self.outcome.observations)
            if self.outcome.authoritative
            else "확인 불가",
            "Errors": ", ".join(d.code.value for d in self.outcome.diagnostics),
        }
        if self.history and self.history[-1]["Run ID"] == self.run_id:
            self.history[-1] = row
        else:
            self.history.append(row)
        self.history = self.history[-20:]
        return self.outcome

    def stop(self):
        self.running = False

    def rows(self):
        if self.result:
            rows = [
                {
                    **asdict(s.observation),
                    "State": "MISSED" if s.miss_count else "OBSERVED",
                    "Instance": s.instance_id,
                    "First Seen": s.first_seen.isoformat(),
                    "Last Seen": s.last_seen.isoformat(),
                    "Miss Count": s.miss_count,
                }
                for s in self.result.active_sessions
            ]
            # Closed events remain explicitly visible in the event/history panel.
            return rows
        return (
            [{**asdict(s), "State": "OBSERVED"} for s in self.outcome.observations]
            if self.outcome
            else []
        )

    def csv(self):
        if not self.observations:
            return ""
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=list(self.observations[0]))
        writer.writeheader()
        writer.writerows(self.observations)
        return stream.getvalue()

    def html(self):
        if not self.outcome:
            return ""
        run = {
            **asdict(self.request),
            "run_id": self.run_id,
            "started_at": self.started,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "status": self.history[-1]["Status"],
        }
        snapshot = RunReportSnapshot(
            run=run,
            controllers=self.outcome.controllers,
            mm_controllers=(self.outcome.used_mm,) if self.outcome.used_mm else (),
            md_controllers=self.outcome.controllers,
            observations=tuple(self.observations),
            observation_total=len(self.observations),
            unique_session_total=len({s["session_key"] for s in self.observations}),
            lifecycle_events=tuple(self.events),
            lifecycle_total=len(self.events),
            lifecycle_counts=(),
            controller_events=(),
            controller_total=0,
            diagnostics=(),
            diagnostic_total=0,
            raw_files=(),
            raw_file_total=0,
            raw_byte_total=0,
            observation_history=tuple(self.observations),
        )
        return render_html_report(snapshot)
