# Public Demo v2 — Session NOC Console

[Current main Live Demo](https://sebia1993-session-tracker-demo.streamlit.app/) · [v2 review branch](https://github.com/sebia1993/aruba-session-tracker-1/tree/codex/public-demo-v2)

This branch is for review. It does not change main or the current Cloud deployment.

```sh
python -m pip install -r portfolio_demo/requirements.txt
python -m streamlit run portfolio_demo/app.py
python -m unittest discover -s portfolio_demo -p test_demo.py -v
```

Use Python 3.13 and `portfolio_demo/app.py` with its adjacent requirements in Cloud.
Inspect Device Settings, enter source/destination IP and optional ports/direction,
then use Current Query or Start Monitoring / Next Poll / Stop. Inputs remain locked
to the active monitor; stop before changing conditions. The virtual network lists
12 clients and multiple TCP/UDP flows. Any valid IPv4 query is accepted and an
unknown client produces the production diagnostic, never an arbitrary allowlist error.

The production path is QueryRequest → TrackerService → SSHCollector command
allowlist → synthetic FixtureFactory → production Parser → QueryOutcome.
MonitorEngine retains its production location cache, required controller scope,
overlap/move detection and authoritative MISS/CLOSED rules. The timeline includes
counter/flags changes, overlap, confirmed move, timeout, miss, parse failure, close,
and re-observation. Fault injection never opens a real connection.

The UI shows Raw, diagnostics, exact command trace, lifecycle details and the latest
20 run summaries. CSV and production HTML export contain the latest run's complete
observations independent of presentation filters. Each run is capped at 50 polls.
Reset discards the entire runtime; there is no shared SQLite, known_hosts, daemon
or credential input. Non-Windows imports of the real service are enabled with a
platform guard; native known_hosts locking still fails closed outside Windows.
Windows locking behavior and the desktop's security boundaries are unchanged.

Fixture and CI results are not live-device or field-PC validation.
