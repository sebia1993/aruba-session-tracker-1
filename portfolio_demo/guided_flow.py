"""Presentation-only navigation of retained execution evidence.

No collection callbacks, network requests, browser storage or generated findings.
Only application-owned scripts execute; timeline values remain HTML-escaped.
"""

from pathlib import Path
from uuid import uuid4

import streamlit as st


def begin():
    st.session_state.guided_run_id = uuid4().hex


class GuidedSlot:
    """Drop-in markdown slot for the existing escaped timeline renderers."""

    def __init__(self, slot, get_run):
        self.slot = slot
        self.get_run = get_run

    def empty(self):
        self.slot.empty()

    def markdown(self, body, **_kwargs):
        run = self.get_run()
        phase = (
            "error"
            if getattr(run, "error", "")
            else "result"
            if getattr(run, "completed", False)
            else "running"
        )
        run_id = st.session_state.get("guided_run_id", "initial")
        title = {
            "running": "현재 실행 과정",
            "result": "실행 완료 · 결과 확인",
            "error": "실행 중단 · 확인 필요",
        }[phase]
        with self.slot.container():
            assets = Path(__file__).parent
            template = (assets / "guided_flow.html.template").read_text(encoding="utf-8")
            for key, value in {"RUN_ID": run_id, "PHASE": phase, "TITLE": title}.items():
                template = template.replace(f"__{key}__", value)
            # Insert the already escaped timeline last; never interpolate it as code.
            template = template.replace("__BODY__", body)
            script = (assets / "guided_flow.js").read_text(encoding="utf-8")
            st.html(template + "<script>" + script + "</script>", unsafe_allow_javascript=True)
