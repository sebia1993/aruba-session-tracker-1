import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from streamlit.testing.v1 import AppTest

from aruba_session_tracker.collectors.ssh import CancellationToken, _known_hosts_file_lock
from portfolio_demo.runtime import DemoRuntime, QueryRequest


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
            source_input = next(
                item for item in app.text_input if item.label == "출발지 IP"
            )
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
            source_input = next(
                item for item in app.text_input if item.label == "출발지 IP"
            )
            self.assertFalse(source_input.disabled)
            other = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run(timeout=30)
            self.assertIsNone(other.session_state.runtime.outcome)
            click("Demo Reset")
            self.assertFalse(app.session_state.runtime.history)
            self.assertIsNone(app.session_state.runtime.monitor)
            next(
                item for item in app.text_input if item.label == "출발지 IP"
            ).set_value("198.51.100.21").run()
            click("현재 조회")
            self.assertEqual(len(app.session_state.runtime.outcome.observations), 3)
            self.assertIsNone(app.session_state.runtime.monitor)
            click("Demo Reset")
            click("샘플 현재 조회")
            self.assertTrue(app.session_state.runtime.outcome.authoritative)
            self.assertEqual(len(app.session_state.runtime.outcome.observations), 3)


if __name__ == "__main__":
    unittest.main()
