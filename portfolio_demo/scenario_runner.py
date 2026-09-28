"""One-click orchestration of the real query/monitor path with synthetic transport."""

from copy import deepcopy
from dataclasses import dataclass, field

from portfolio_demo.execution_trace import ExecutionTrace
from portfolio_demo.runtime import CONFIG, DemoRuntime, QueryRequest

SCENARIOS = {
    "normal": "정상 통신 추적",
    "closure": "세션 종료 추적",
    "failure": "Session 수집 실패",
}


@dataclass
class PollSnapshot:
    poll: int
    title: str
    explanation: str
    outcome: object
    result: object
    rows: list
    trace: ExecutionTrace
    observed: int | None
    retained: int
    missed: int
    closed: int
    selected_controllers: list


@dataclass
class ScenarioRun:
    key: str
    name: str
    planned_polls: int
    snapshots: list = field(default_factory=list)
    current_poll: int = 0
    completed: bool = False
    error: str = ""


class ScenarioRunner:
    def __init__(self, config=CONFIG):
        self.config = config
        self.runtime = DemoRuntime(config)
        self.run = None

    def play(self, key, on_change=None):
        if key not in SCENARIOS:
            raise ValueError("지원하지 않는 시나리오입니다.")
        self.runtime = DemoRuntime(self.config)
        r = self.runtime
        # This chooses only synthetic input. Counts and lifecycle are engine outputs.
        modes = ["normal"]
        if key == "closure":
            modes += ["empty"] * r.service.config.close_after_misses
        elif key == "failure":
            modes.append("timeout")
        self.run = ScenarioRun(key, SCENARIOS[key], len(modes))
        if on_change:
            r.execution.on_change = lambda: on_change(self)
        try:
            for index, mode in enumerate(modes):
                self.run.current_poll = index + 1
                if on_change:
                    on_change(self)
                if index == 0:
                    r.start(QueryRequest("198.51.100.10", ""), monitor=True, mode=mode)
                else:
                    if mode == "timeout":
                        # Advance the existing injected clock so the engine also
                        # rechecks MM location before the synthetic MD timeout.
                        r.virtual_time += r.service.config.location_interval_seconds
                    r.poll(mode)
                self.run.snapshots.append(self._snapshot())
                if on_change:
                    on_change(self)
            self.run.completed = True
        except Exception as exc:
            self.run.error = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            r.stop()
            r.execution.on_change = None
            if on_change:
                on_change(self)
        return self.run

    def _snapshot(self):
        r = self.runtime
        outcome, result = r.outcome, r.result
        observed = len(outcome.observations) if outcome.authoritative else None
        retained = len(result.active_sessions)
        missed = max((s.miss_count for s in result.active_sessions), default=0)
        closed = sum(e.event_type.value == "CLOSED" for e in result.events)
        controllers = list(
            dict.fromkeys(entry["Device"] for entry in r.trace if entry["Stage"] == "MD_QUERY")
        ) or list(outcome.controllers)
        if not outcome.authoritative:
            title = "수집 실패 · 확인 불가"
            explanation = (
                "Session 조회가 완료되지 않았습니다. "
                f"기존 추적 {retained}개를 유지하며 세션 종료로 판단하지 않습니다."
            )
        elif closed:
            title = "CLOSED · 종료 확인"
            threshold = r.service.config.close_after_misses
            explanation = (
                f"유효한 조회에서 연속 미관측 기준 {threshold}회가 충족되어 "
                f"{closed}개 세션의 종료를 확인했습니다."
            )
        elif missed:
            title = f"MISSED {missed} · 종료 판단 보류"
            explanation = (
                f"현재 조건에 맞는 세션은 관측되지 않았습니다. 미관측 "
                f"{missed}/{r.service.config.close_after_misses}회이므로 "
                f"기존 {retained}개 세션을 추적하며 종료 판단을 보류합니다."
            )
        elif observed:
            title = "OBSERVED · 통신 관측"
            explanation = (
                f"입력한 단말은 {', '.join(outcome.controllers)}에서 확인되었고, "
                f"현재 {observed}개의 통신 세션 관측 행이 확인되었습니다."
            )
        else:
            title = "현재 관측 없음"
            explanation = "단말 위치는 확인됐지만 현재 조건에 맞는 세션은 관측되지 않았습니다."
        trace = ExecutionTrace()
        trace.steps = deepcopy(r.execution.steps)
        trace.label = f"Poll #{r.poll_count} · {title}"
        trace.elapsed_ms = r.execution.elapsed_ms
        return PollSnapshot(
            r.poll_count,
            title,
            explanation,
            deepcopy(outcome),
            deepcopy(result),
            deepcopy(r.rows()),
            trace,
            observed,
            retained,
            missed,
            closed,
            controllers,
        )


def communication_rows(observations):
    """Keep every direction/controller observation; do not infer application services."""
    return [
        {
            "controller": item.controller_name,
            "source": f"{item.source_ip}:{item.source_port}",
            "destination": f"{item.destination_ip}:{item.destination_port}",
            "protocol": {6: "TCP", 17: "UDP"}.get(item.protocol, str(item.protocol)),
        }
        for item in observations
    ]
