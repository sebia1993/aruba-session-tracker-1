# Aruba Session Tracker — Public Web Edition

**[고정 Live URL](https://sebia1993-session-tracker-demo.streamlit.app/)** · [GitHub Source](https://github.com/sebia1993/aruba-session-tracker-1)

이 앱은 별도의 포트폴리오 시뮬레이터가 아니라 **Desktop `Aruba Session Tracker`의 Web Edition**입니다.

## Desktop → Web 매핑

| Desktop UI | Public Web Edition |
|---|---|
| 상단 MM/MD/조회주기/최근확인/상태 Chip | 동일 Header Chip |
| 세션 조회 탭 | 동일 `세션 조회` 탭 |
| 로그인 정보 그룹 | Public Demo에서는 비활성 상태로 동일 위치 표시 |
| 출발지/목적지·양방향·고급 포트 조건 | 동일 Query 입력 |
| 지속 모니터링 / 현재 조회 / 중지 | 동일 작업 버튼 |
| 결과 Metrics + 세션 결과표 | 동일 운영 지표와 결과표 |
| 선택한 세션 조사 | 세션 요약 / 선택 행 Raw / 진단 이벤트 |
| 장비 설정 탭 | MM / MD / 모니터링 판정 기준 |
| 기록 및 내보내기 탭 | History / CSV / HTML / 기록 정리 |

Public Web Edition의 차이는 **실제 SSH와 자격 증명 입력을 차단하고 FixtureFactory를 Transport로 사용하는 것**뿐입니다. QueryRequest, TrackerService, production Parser, MonitorEngine과 HTML Report는 원 프로젝트 코드를 재사용합니다.

Streamlit Community Cloud는 기존 repository `sebia1993/aruba-session-tracker-1`, branch `main`, entrypoint `portfolio_demo/app.py`를 계속 사용합니다. **Live URL은 변경하지 않습니다.**

자동 fixture/CI 결과와 실제 Aruba 장비·현장 PC 검증은 같은 증거 수준으로 표현하지 않습니다.
