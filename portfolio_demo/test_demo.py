import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from streamlit.testing.v1 import AppTest

from aruba_session_tracker.collectors.ssh import CancellationToken, _known_hosts_file_lock
from portfolio_demo.runtime import CONFIG, DemoRuntime, QueryRequest
from portfolio_demo.scenario_runner import ScenarioRunner, communication_rows


class DemoTests(unittest.TestCase):
    def test_queries_route_filter_and_accept_other_clients(self):
        with patch("socket.create_connection", side_effect=AssertionError("No network")):
            r = DemoRuntime()
            first = r.start(QueryRequest("198.51.100.10", ""))
            self.assertTrue(first.authoritative)
            self.assertEqual(len(first.observations), 3)
            self.assertEqual(first.controllers, ("DEMO-MD-03",))
            self.assertEqual(
                len(
                    r.start(
                        QueryRequest("198.51.100.10", "", destination_port=443, bidirectional=False)
                    ).observations
                ),
                1,
            )
            self.assertEqual(
                len(
                    r.start(
                        QueryRequest("198.51.100.10", "", destination_port=443, bidirectional=True)
                    ).observations
                ),
                2,
            )
            other = r.start(QueryRequest("198.51.100.21", ""))
            self.assertEqual(len(other.observations), 3)
            self.assertNotEqual(first.controllers, other.controllers)
            dest = r.start(QueryRequest("", "198.51.100.21"))
            self.assertTrue(dest.authoritative)
            self.assertTrue(dest.observations)
            both = r.start(QueryRequest("198.51.100.10", "203.0.113.21"))
            self.assertEqual(set(both.controllers), {"DEMO-MD-03", "DEMO-MD-02"})
            absent = r.start(QueryRequest("198.51.100.250", ""))
            self.assertTrue(absent.diagnostics)
            self.assertFalse(absent.authoritative)
            self.assertFalse(absent.observations)
            with self.assertRaises(ValueError):
                QueryRequest("bad; command", "")
            with self.assertRaises(ValueError):
                QueryRequest("", "")

    def test_monitor_overlap_move_failures_miss_close_and_exports(self):
        with patch("socket.create_connection", side_effect=AssertionError("No network")):
            r = DemoRuntime()
            r.start(QueryRequest("198.51.100.10", ""), monitor=True)
            r.poll()
            self.assertTrue(any(e.event_type.value == "FLAGS_CHANGED" for e in r.result.events))
            r.poll()
            self.assertEqual(len(r.outcome.observations), 6)
            self.assertFalse(
                any(e.event_type.value == "CONTROLLER_CHANGED" for e in r.result.events)
            )
            r.poll()
            self.assertTrue(
                any(e.event_type.value == "CONTROLLER_CHANGED" for e in r.result.events)
            )
            for tick, expected_misses in [(4, 0), (5, 1), (6, 1), (7, 2)]:
                r.poll()
                self.assertTrue(
                    all(s.miss_count == expected_misses for s in r.result.active_sessions)
                )
                if tick in (4, 6):
                    self.assertFalse(r.outcome.authoritative)
                    self.assertFalse(r.result.events)
            r.poll()
            self.assertFalse(r.result.active_sessions)
            self.assertTrue(all(e.event_type.value == "CLOSED" for e in r.result.events))
            r.poll()
            self.assertTrue(r.result.active_sessions)
            self.assertIn("source_ip", r.csv())
            self.assertIn("198.51.100.10", r.html())
            self.assertNotIn("show datapath", r.html())
            self.assertNotIn("synthetic-not-a-secret", r.html())
            for entry in r.factory.trace:
                self.assertNotEqual(entry["Command"], "show datapath session table")

    def test_ui_counters_filters_and_empty_diagnostics(self):
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        runtime = app.session_state.runtime
        runtime.start(QueryRequest("198.51.100.10", ""), monitor=True)
        app.run()
        self.assertFalse(app.exception)
        metrics = {item.label: item.value for item in app.metric}
        self.assertEqual(metrics["Bytes"], str(runtime.rows()[0]["bytes_count"]))
        next(item for item in app.text_input if item.label == "결과 검색").set_value(
            "no-match"
        ).run()
        self.assertEqual(
            next(item.value for item in app.metric if item.label == "결과표 표시 행"), "0"
        )
        runtime.poll("timeout")
        app = AppTest.from_file(str(Path(__file__).with_name("app.py")))
        app.session_state.runtime = runtime
        app.run()
        self.assertEqual(
            next(item.value for item in app.metric if item.label == "현재 관측 흐름"), "확인 불가"
        )
        runtime.start(QueryRequest("198.51.100.250", ""))
        app = AppTest.from_file(str(Path(__file__).with_name("app.py")))
        app.session_state.runtime = runtime
        app.run()
        self.assertFalse(runtime.rows())
        self.assertTrue(any(item.label == "수집 진단 · 전체 Raw" for item in app.expander))
        runtime.start(QueryRequest("198.51.100.10", ""), monitor=True)
        for _ in range(8):
            runtime.poll()
        app = AppTest.from_file(str(Path(__file__).with_name("app.py")))
        app.session_state.runtime = runtime
        app.run()
        self.assertFalse(runtime.rows())
        self.assertTrue(any(item.label == "Lifecycle Events" for item in app.expander))
        self.assertFalse(app.exception)

    def test_native_lock_fails_closed_outside_windows(self):
        with tempfile.TemporaryDirectory() as root, patch("sys.platform", "linux"):
            path = Path(root) / "known_hosts"
            with (
                self.assertRaisesRegex(RuntimeError, "requires Windows"),
                _known_hosts_file_lock(path, CancellationToken()),
            ):
                pass
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_ui_monitor_query_lock_stop_reset_and_session_isolation(self):
        with patch("socket.create_connection", side_effect=AssertionError("No network")):
            app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run(timeout=30)

            def click(label):
                next(b for b in app.button if b.label == label).click().run(timeout=30)
                self.assertFalse(app.exception)

            click("지속 모니터링 시작")
            source_input = next(item for item in app.text_input if item.label == "출발지 IP")
            self.assertTrue(source_input.disabled)
            for _ in range(3):
                click("다음 Poll")
            self.assertTrue(
                any(
                    e["event_type"] == "CONTROLLER_CHANGED"
                    for e in app.session_state.runtime.events
                )
            )
            click("중지")
            source_input = next(item for item in app.text_input if item.label == "출발지 IP")
            self.assertFalse(source_input.disabled)
            other = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run(timeout=30)
            self.assertIsNone(other.session_state.runtime.outcome)
            click("Demo Reset")
            self.assertFalse(app.session_state.runtime.history)
            self.assertIsNone(app.session_state.runtime.monitor)
            next(item for item in app.text_input if item.label == "출발지 IP").set_value(
                "198.51.100.21"
            ).run()
            click("현재 조회")
            self.assertEqual(len(app.session_state.runtime.outcome.observations), 3)
            self.assertIsNone(app.session_state.runtime.monitor)
            click("Demo Reset")
            click("샘플 현재 조회")
            self.assertTrue(app.session_state.runtime.outcome.authoritative)
            self.assertEqual(len(app.session_state.runtime.outcome.observations), 3)

    def test_execution_trace_tracks_real_outcomes_and_timeout(self):
        r = DemoRuntime()
        updates = []
        r.execution.on_change = lambda: updates.append([s.status for s in r.execution.steps])
        outcome = r.start(QueryRequest("198.51.100.10", ""), monitor=True)
        steps = {s.id: s for s in r.execution.steps}
        self.assertTrue(
            {"input", "collect", "route", "location", "parser", "lifecycle"} <= steps.keys()
        )
        self.assertEqual(steps["parser"].evidence["observations"], len(outcome.observations))
        self.assertEqual(steps["location"].evidence["used_mm"], outcome.used_mm)
        self.assertTrue(any("running" in update for update in updates))
        before = {s.instance_id for s in r.result.active_sessions}
        r.poll("timeout")
        steps = {s.id: s for s in r.execution.steps}
        self.assertIsNone(steps["parser"].evidence["observations"])
        self.assertEqual(steps["lifecycle"].evidence["closed"], 0)
        self.assertEqual(before, {s.instance_id for s in r.result.active_sessions})
        self.assertIn("종료로 판단하지 않음", steps["lifecycle"].detail)
        self.assertTrue(any(s.status == "failure" for s in r.execution.steps))
        r.start(QueryRequest("198.51.100.10", ""), monitor=True)
        for _ in range(8):
            r.poll()
        lifecycle = next(s for s in r.execution.steps if s.id == "lifecycle")
        self.assertEqual(lifecycle.evidence["closed"], len(r.result.events))
        self.assertEqual(lifecycle.evidence["observed"], 0)
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        next(b for b in app.button if b.label == "현재 조회").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(
            any("실행 과정" in m.value and "Session Parser" in m.value for m in app.markdown)
        )
        self.assertEqual(next(m.value for m in app.metric if m.label == "결과표 표시 행"), "3")


class ScenarioTests(unittest.TestCase):
    def test_normal_routes_parses_and_builds_each_actual_direction(self):
        runner = ScenarioRunner()
        with patch("socket.create_connection", side_effect=AssertionError("No network")):
            run = runner.play("normal")
        snap = run.snapshots[0]
        self.assertTrue(run.completed)
        self.assertEqual(snap.observed, len(runner.runtime.outcome.observations))
        self.assertEqual(snap.outcome.used_mm, "DEMO-MM-PRIMARY")
        self.assertEqual(snap.selected_controllers, ["DEMO-MD-03"])
        self.assertIsNotNone(runner.runtime.monitor)
        self.assertFalse(runner.runtime.running)
        flows = communication_rows(snap.outcome.observations)
        self.assertEqual(len(flows), snap.observed)
        for flow, observation in zip(flows, snap.outcome.observations, strict=True):
            self.assertEqual(
                flow["destination"], f"{observation.destination_ip}:{observation.destination_port}"
            )
            self.assertEqual(flow["source"], f"{observation.source_ip}:{observation.source_port}")
        self.assertTrue(any(f["source"].startswith("203.0.113.") for f in flows))
        self.assertTrue(
            all(
                entry["Command"] != "show datapath session table"
                for entry in runner.runtime.factory.trace
            )
        )

    def test_close_uses_real_configured_miss_threshold(self):
        for threshold in (2, 3, 5):
            runner = ScenarioRunner(replace(CONFIG, close_after_misses=threshold))
            run = runner.play("closure")
            self.assertEqual(len(run.snapshots), 1 + threshold)
            initial = run.snapshots[0].retained
            self.assertGreater(initial, 0)
            for n, snap in enumerate(run.snapshots[1:-1], 1):
                self.assertTrue(snap.outcome.authoritative)
                self.assertEqual(snap.observed, 0)
                self.assertEqual(snap.missed, n)
                self.assertEqual(snap.closed, 0)
                self.assertEqual(snap.retained, initial)
            last = run.snapshots[-1]
            self.assertEqual(last.closed, initial)
            self.assertEqual(last.retained, 0)
            self.assertTrue(
                all(
                    e.miss_count == threshold
                    for e in last.result.events
                    if e.event_type.value == "CLOSED"
                )
            )
            self.assertEqual(last.rows, runner.runtime.rows())
            self.assertEqual(run.snapshots[0].retained, initial)

    def test_timeout_preserves_instances_and_misses_and_rechecks_location(self):
        runner = ScenarioRunner()
        run = runner.play("failure")
        before, after = run.snapshots
        self.assertIsNone(after.observed)
        self.assertFalse(after.outcome.authoritative)
        self.assertEqual(after.closed, 0)
        self.assertEqual(after.retained, before.retained)
        self.assertEqual(after.result.active_sessions, before.result.active_sessions)
        self.assertEqual(after.outcome.used_mm, before.outcome.used_mm)
        self.assertEqual(after.selected_controllers, before.selected_controllers)
        self.assertTrue(
            any(
                s.id == "location" and s.status == "success" and s.evidence.get("locations")
                for s in after.trace.steps
            )
        )
        self.assertTrue(any(s.id == "collect" and s.status == "failure" for s in after.trace.steps))
        self.assertFalse(after.result.events)
        self.assertIn("MD_UNREACHABLE", {d.code.value for d in after.outcome.diagnostics})

    def test_trace_counters_match_every_outcome_and_remain_independent(self):
        runner = ScenarioRunner()
        for key in ("normal", "closure", "failure"):
            run = runner.play(key)
            for snap in run.snapshots:
                steps = {s.id: s for s in snap.trace.steps}
                self.assertTrue(
                    {"location", "route", "collect", "parser", "lifecycle"} <= steps.keys()
                )
                self.assertEqual(steps["parser"].evidence["observations"], snap.observed)
                self.assertEqual(steps["lifecycle"].evidence["retained"], snap.retained)
                self.assertEqual(steps["lifecycle"].evidence["closed"], snap.closed)
                self.assertIsNotNone(snap.trace.elapsed_ms)
                self.assertTrue(all(s.status != "running" for s in snap.trace.steps))
            self.assertIsNot(run.snapshots[0].trace, runner.runtime.execution)

    def test_one_click_ui_flow_counts_filters_and_manual_controls(self):
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        next(b for b in app.button if b.label == "대표 통신 추적 실행").click().run()
        self.assertFalse(app.exception)
        runtime = app.session_state.runtime
        count = len(runtime.outcome.observations)
        self.assertTrue(app.session_state.scenario_runner.run.completed)
        metrics = {m.label: m.value for m in app.metric}
        self.assertEqual(metrics["현재 관측 흐름"], str(count))
        self.assertEqual(metrics["결과표 표시 행"], str(len(runtime.rows())))
        self.assertTrue(
            any(
                "Communication Flow" in m.value
                and "DEMO-MD-03" in m.value
                and "203.0.113." in m.value
                for m in app.markdown
            )
        )
        self.assertTrue(any("Scenario Timeline" in m.proto.body for m in app.get("html")))
        self.assertTrue(any("Execution Trace" in m.value for m in app.markdown))
        next(s for s in app.selectbox if s.label == "Protocol").select("TCP").run()
        metrics = {m.label: m.value for m in app.metric}
        self.assertEqual(metrics["현재 관측 흐름"], str(count))
        expected = sum(row["protocol"] == 6 for row in runtime.rows())
        self.assertEqual(metrics["결과표 표시 행"], str(expected))
        advanced = next(e for e in app.expander if e.label == "고급 직접 조회")
        self.assertTrue(any(t.label == "출발지 IP" for t in advanced.get("text_input")))
        for label in ("세션 종료 추적", "Session 수집 실패", "정상 통신 추적"):
            next(b for b in app.button if b.label == label).click().run()
            self.assertFalse(app.exception)
            self.assertTrue(app.session_state.scenario_runner.run.completed)
            if label == "Session 수집 실패":
                metrics = {m.label: m.value for m in app.metric}
                self.assertEqual(metrics["현재 관측 흐름"], "확인 불가")
                self.assertEqual(metrics["결과표 표시 행"], str(count))
                self.assertTrue(any("이전 관측" in m.value for m in app.markdown))
            if label == "세션 종료 추적":
                self.assertFalse(app.session_state.runtime.rows())
                self.assertTrue(any("CLOSED" in m.value for m in app.markdown))
        next(b for b in app.button if b.label == "현재 조회").click().run()
        self.assertFalse(app.exception)
        self.assertNotIn("scenario_runner", app.session_state)

    def test_rerun_preserves_scenario_and_selected_trace_without_polling(self):
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        next(b for b in app.button if b.label == "세션 종료 추적").click().run()
        count = app.session_state.runtime.poll_count
        next(s for s in app.selectbox if s.label == "Poll별 Execution Trace").select(0).run()
        self.assertEqual(app.session_state.runtime.poll_count, count)
        self.assertTrue(
            any("OBSERVED" in m.value and "Execution Trace" in m.value for m in app.markdown)
        )
        self.assertFalse(app.session_state.runtime.rows())
        self.assertTrue(app.session_state.scenario_runner.run.completed)


if __name__ == "__main__":
    unittest.main()


class GuidedFlowTests(unittest.TestCase):
    def test_navigation_keeps_execution_identity_and_results_on_rerun(self):
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        next(b for b in app.button if b.label == "대표 통신 추적 실행").click().run()
        self.assertFalse(app.exception)
        token = app.session_state.guided_run_id
        runner = app.session_state.scenario_runner
        runtime = app.session_state.runtime
        html = next(h.proto.body for h in app.get("html") if 'id="guided-flow"' in h.proto.body)
        self.assertIn('data-phase="result"', html)
        self.assertIn('aria-label="실행 단계 선택"', html)
        app.run()
        self.assertFalse(app.exception)
        self.assertEqual(token, app.session_state.guided_run_id)
        self.assertIs(runner, app.session_state.scenario_runner)
        self.assertIs(runtime, app.session_state.runtime)
        next(b for b in app.button if b.label == "대표 통신 추적 실행").click().run()
        self.assertNotEqual(token, app.session_state.guided_run_id)
