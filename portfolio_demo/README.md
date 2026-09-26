# Public Streamlit Demo

**[Live Demo](https://sebia1993-session-tracker-demo.streamlit.app/)** · [GitHub Source](https://github.com/sebia1993/aruba-session-tracker-1)

별도 장비와 계정 없이 원 프로젝트의 Python 분석 로직을 실행합니다.
비식별 문서 주소와 합성 CLI만 사용하며, 외부 연결·내부 파일 업로드는 지원하지 않습니다.

```sh
python -m venv .venv-demo
# 가상환경 활성화 후
python -m pip install -r portfolio_demo/requirements.txt
python -m streamlit run portfolio_demo/app.py
python -m unittest discover -s portfolio_demo -p test_demo.py -v
```

Streamlit Community Cloud: repository `sebia1993/aruba-session-tracker-1`, branch `main`,
entrypoint `portfolio_demo/app.py`, Python 3.13.
의존성은 entrypoint 옆 `portfolio_demo/requirements.txt`를 사용합니다.
기존 Windows 앱의 런타임 잠금 파일과 패키징 경로는 유지합니다.

시나리오 선택 → 분석 실행 → Summary → 상세 결과 → Raw/Evidence 흐름입니다.
입력을 변경하면 기존 결과의 시나리오를 표시하며 다시 실행해야 갱신합니다.
각 실행은 독립된 분석 상태로 시작하고 결과는 브라우저 세션별로 분리합니다.
Fixture·AppTest·Windows CI는 실제 장비/운영망 검증이 아닙니다.
