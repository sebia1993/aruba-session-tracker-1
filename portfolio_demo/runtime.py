"""Session-local TrackerService / MonitorEngine orchestration, no database."""

import csv
import io
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aruba_session_tracker.models import Credentials  # noqa: E402
from aruba_session_tracker.models import QueryRequest as QueryRequest  # noqa: E402
from aruba_session_tracker.services.monitoring import MonitorEngine  # noqa: E402
from aruba_session_tracker.services.tracker import TrackerCallbacks, TrackerService  # noqa: E402
from aruba_session_tracker.storage.html_report import (  # noqa: E402
    RunReportSnapshot,
    render_html_report,
)
from portfolio_demo.execution_trace import ExecutionTrace, traced  # noqa: E402
from portfolio_demo.fixture_transport import CONFIG, STAGES, FixtureFactory  # noqa: E402


class EvidenceTrackerService(TrackerService):
    """Observe the production location result without changing routing or parsing."""

    def _resolve_locations(self, *args, **kwargs):
        with self.execution.step("location", "MM 위치 조회 / Production Parser") as step:
            result = super()._resolve_locations(*args, **kwargs)
            locations = (
                [item for item in (result.source, result.destination) if item] if result else []
            )
            step.status = (
                "success"
                if locations and set(args[0].client_ips) <= {item.client_ip for item in locations}
                else "warning"
            )
            step.detail = (result.used_mm or "확인 불가") if result else "MM 위치 확인 불가"
            step.detail += " · " + (
                " / ".join(f"{item.client_ip} → {item.current_switch}" for item in locations)
                or "단말 위치 확인 불가"
            )
            step.evidence = {
                "used_mm": result.used_mm if result else None,
                "locations": [asdict(item) for item in locations],
            }
            return result


class DemoRuntime:
    def __init__(self, config=CONFIG):
        self.config = config
        self.execution = ExecutionTrace()
        self.factory = FixtureFactory(config)
        self.factory.execution = self.execution
        self.trace = []
        self.service = EvidenceTrackerService(
            config, self.factory, TrackerCallbacks(progress=self._progress)
        )
        self.service.execution = self.execution
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
        if stage == "MD_QUERY":
            self.execution.record(
                "route", "조회 대상 MD 결정", "success", device, {"controller": device}
            )

    @traced("세션 조회")
    def start(self, request, monitor=False, mode="timeline"):
        if self.running:
            self.stop()
        with self.execution.step("input", "입력 검증") as step:
            # Reconstruct the validated production request, not a separate demo validator.
            request = QueryRequest(**asdict(request))
            step.evidence = asdict(request)
            step.detail = (
                f"Source {request.source_ip or '미지정'} → "
                f"Destination {request.destination_ip or '미지정'}"
            )
        self.request = request
        self.run_id = str(uuid4())
        self.started = datetime.now(UTC).isoformat()
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

    @traced("세션 Poll")
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
        self.virtual_time += self.config.session_interval_seconds
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
        outcome = self.outcome
        mm_commands = [
            entry for entry in self.factory.trace if entry["Command"].startswith("show global-user")
        ]
        if not mm_commands:
            self.execution.record(
                "location",
                "MM 위치 조회 결과",
                "success" if outcome.used_mm else "warning",
                f"{outcome.used_mm or '확인 불가'} → "
                f"{', '.join(outcome.controllers) or '응답 MD 확인 불가'}"
                + (" · 이전 위치 관측 재사용" if not mm_commands else ""),
                {
                    "used_mm": outcome.used_mm,
                    "controllers": list(outcome.controllers),
                    "cached": not bool(mm_commands),
                },
            )
        self.execution.record(
            "parser",
            "Production Session Parser",
            "success" if outcome.authoritative else "warning",
            f"{len(outcome.observations)}개 Session 관측"
            if outcome.authoritative
            else f"완전한 관측 확인 불가 · 확보한 행 {len(outcome.observations)} · "
            + ", ".join(d.code.value for d in outcome.diagnostics),
            {
                "observations": len(outcome.observations) if outcome.authoritative else None,
                "partial_observations": len(outcome.observations),
                "authoritative": outcome.authoritative,
            },
        )
        observed = (
            sum(not item.miss_count for item in self.result.active_sessions)
            if self.result
            else len(outcome.observations)
        )
        closed = (
            sum(event.event_type.value == "CLOSED" for event in self.result.events)
            if self.result
            else 0
        )
        retained = len(self.result.active_sessions) if self.result else len(outcome.observations)
        self.execution.record(
            "lifecycle",
            "MonitorEngine / Lifecycle" if self.monitor else "현재 조회 결과",
            "success" if outcome.authoritative else "warning",
            f"OBSERVED {observed} · CLOSED {closed} · 추적 {retained}"
            if outcome.authoritative
            else f"기존 추적 {retained}개 유지 · 수집 실패를 세션 종료로 판단하지 않음",
            {
                "observed": observed if outcome.authoritative else None,
                "closed": closed,
                "retained": retained,
            },
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
        row = {
            "Run ID": self.run_id,
            "Query": str(asdict(self.request)),
            "Started": self.started,
            "Polls": self.poll_count,
            "Status": self.run_status,
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

    @property
    def run_status(self):
        """Describe the current outcome independently of removable history summaries."""
        if self.outcome is None:
            return ""
        if self.outcome.authoritative:
            return "COMPLETED"
        return "PARTIAL" if self.outcome.observations else "FAILED"

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
            "ended_at": datetime.now(UTC).isoformat(),
            "status": self.run_status,
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
