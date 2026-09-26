import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from streamlit.testing.v1 import AppTest

from portfolio_demo.logic import SCENARIOS, run_demo


class DemoTests(unittest.TestCase):
    def test_all_scenarios_through_ui_without_network(self):
        for scenario in SCENARIOS:
            with (
                self.subTest(scenario=scenario),
                patch("socket.create_connection", side_effect=AssertionError("No network")),
            ):
                app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run(timeout=20)
                self.assertFalse(app.exception)
                app.selectbox[0].select(scenario).run()
                next(b for b in app.button if b.label == "분석 실행").click().run(timeout=20)
                self.assertFalse(app.exception)
                self.assertTrue(app.metric)
                self.assertTrue(app.dataframe)
                # Re-render must retain the result without re-running analysis.
                app.run()
                self.assertFalse(app.exception)
                self.assertIn("result", app.session_state)

    def test_empty_and_failure_are_distinct(self):
        for client in ("192.0.2.10", "192.0.2.20", "192.0.2.30"):
            active = run_demo("sessions", client)
            self.assertEqual(len(active["rows"]), 3)
            self.assertTrue(active["authoritative"])
            self.assertEqual(active["context"][0]["client_ip"], client)
        empty = run_demo("empty", "192.0.2.10")
        self.assertTrue(empty["authoritative"])
        self.assertEqual(empty["status"], "No Active Session")
        for scenario in ("collection_failed", "parse_failed"):
            failed = run_demo(scenario, "192.0.2.10")
            self.assertFalse(failed["authoritative"])
            self.assertIn("Unknown", failed["status"])
        with self.assertRaises(ValueError):
            run_demo("sessions", "8.8.8.8")

    def test_filter_history_and_browser_isolation(self):
        app = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        next(b for b in app.button if b.label == "분석 실행").click().run()
        app.text_input[1].input("UDP").run()
        self.assertEqual(len(app.dataframe[1].value), 1)
        self.assertEqual(len(app.session_state["history"]), 1)
        other = AppTest.from_file(str(Path(__file__).with_name("app.py"))).run()
        self.assertNotIn("result", other.session_state)


if __name__ == "__main__":
    unittest.main()
