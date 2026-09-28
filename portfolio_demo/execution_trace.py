"""Bounded execution evidence; timings measure real calls, never simulated delays."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from html import escape
from time import perf_counter


@dataclass
class ExecutionStep:
    id: str
    label: str
    status: str = "running"
    detail: str = ""
    evidence: dict = field(default_factory=dict)
    elapsed_ms: float | None = None


class ExecutionTrace:
    def __init__(self):
        self.steps = []
        self.label = ""
        self.elapsed_ms = None
        self.on_change = None
        self.depth = 0

    def notify(self):
        if self.on_change:
            self.on_change()

    @contextmanager
    def operation(self, label):
        outer = self.depth == 0
        if outer:
            self.steps = []
            self.label = label
            self.elapsed_ms = None
            started = perf_counter()
        self.depth += 1
        try:
            self.notify()
            yield
        except Exception as exc:
            if outer:
                self.record("execution_error", "실행 중단", "failure", type(exc).__name__)
            raise
        finally:
            self.depth -= 1
            if outer:
                self.elapsed_ms = (perf_counter() - started) * 1000
                self.notify()

    def record(self, id, label, status, detail, evidence=None):
        step = ExecutionStep(id, label, status, detail, evidence or {})
        self.steps.append(step)
        self.steps = self.steps[-100:]
        self.notify()
        return step

    @contextmanager
    def step(self, id, label, detail=""):
        step = self.record(id, label, "running", detail)
        started = perf_counter()
        try:
            yield step
            if step.status == "running":
                step.status = "success"
        except Exception as exc:
            if step.status != "failure":
                step.detail = type(exc).__name__
            step.status = "failure"
            raise
        finally:
            step.elapsed_ms = (perf_counter() - started) * 1000
            self.notify()


def traced(label):
    def decorate(fn):
        @wraps(fn)
        def run(self, *args, **kwargs):
            with self.execution.operation(label):
                return fn(self, *args, **kwargs)

        return run

    return decorate


def render_trace(trace, slot):
    if not trace.steps:
        slot.empty()
        return
    state = (
        "실행 중"
        if trace.elapsed_ms is None
        else (
            "확인 필요"
            if any(s.status in ("failure", "warning") for s in trace.steps)
            else "실행 완료"
        )
    )
    duration = "" if trace.elapsed_ms is None else f" · {trace.elapsed_ms:.1f} ms"
    icons = {"running": "◌", "success": "✓", "warning": "⚠", "failure": "✕"}
    rows = []
    for step in trace.steps:
        timing = "" if step.elapsed_ms is None else f" · {step.elapsed_ms:.1f} ms"
        rows.append(
            '<div style="padding:.35rem 0;border-bottom:1px solid #8883">'
            f"<b>{icons[step.status]} {escape(step.label)}</b>{timing}<br>"
            f"<span>{escape(step.detail)}</span></div>"
        )
    slot.markdown(
        '<section aria-label="Execution Trace" style="border:1px solid #8885;'
        'border-radius:10px;padding:1rem;margin:.5rem 0;overflow-wrap:anywhere">'
        f"<h3>실행 과정 · {escape(trace.label)}</h3><b>{state}{duration}</b>"
        + "".join(rows)
        + '<p style="font-size:.8rem;opacity:.7">합성 입력 → 실제 분석 코어 · '
        "시간은 실제 호출 기준이며, 별도 측정하지 않은 결과 단계는 시간을 표시하지 않습니다.</p>"
        "</section>",
        unsafe_allow_html=True,
    )
