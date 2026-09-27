# Public Demo v2 구현 계획 — Aruba Session Tracker

## 목적

현재 `portfolio_demo`는 3개의 고정 Client와 4개의 시나리오에 대해 Parser를 실행한다. Parser 재사용은 적절하지만 원본 프로그램의 핵심인 **조회 조건 입력 → MM 위치 확인 → 관련 MD 라우팅 → 현재 조회/지속 모니터링 → 수명주기 변화 → 이력/Raw/Export** 경험이 충분히 재현되지 않는다.

Public Demo v2는 원본 NOC 콘솔의 사용 흐름을 브라우저에서 체험할 수 있게 한다. Aruba Wireless Policy Mapper는 production workflow를 UI에서 직접 호출하는 구조만 품질 기준으로 참고한다.

## 원본 프로그램 실제 흐름

1. 장비 설정 탭에서 Primary/Standby MM과 여러 MD 확인
2. 이번 실행에만 SSH 계정 입력
3. 세션 조회 탭에서 출발지 IP / 목적지 IP 중 하나 이상 입력
4. 선택적으로 Source Port / Destination Port / 양방향 조건 입력
5. `현재 조회` 또는 `지속 모니터링 시작`
6. MM `global-user-table`에서 Client 위치 확인
7. 관련 MD만 선택하여 필터형 datapath 명령 실행
8. 세션 Observation 표시
9. 지속 모니터링에서는 OBSERVED/MISSED/CLOSED, Controller 변경, Flags/Counter 변화 추적
10. Raw CLI, 진단 이벤트 확인
11. 실행 이력 확인
12. CSV / HTML 내보내기

Public Demo도 이 순서를 중심으로 한다.

## 핵심 원칙

- 실제 SSH 연결은 하지 않는다.
- 무필터 전체 datapath 조회를 만들지 않는다.
- 임의 CLI 문자열을 조합해 실행하는 UI를 만들지 않는다.
- `QueryRequest`, `TrackerService`, `MonitorEngine`, production Parser/commands를 최대한 재사용한다.
- 현재의 `CLIENTS = {...3개...}` 고정 정답 구조를 제거한다.
- 수집 실패/파싱 실패에서 세션을 CLOSED로 만들지 않는다.
- Public Demo의 가상 네트워크에 존재하는 여러 Client/flow 중 사용자가 조건으로 검색하도록 한다.

## Demo Network

비식별 합성 환경:
- DEMO-MM-PRIMARY
- DEMO-MM-STANDBY
- DEMO-MD-01 ~ DEMO-MD-04
- 여러 Client IP
- 여러 Destination
- 여러 TCP/UDP flow

fixture transport는 입력된 `QueryRequest`에 따라 production command/query path가 실제로 달라지도록 한다.

사용자가 볼 수 있는 Sample 버튼은 있어도 되지만 고정 정답 3개 중 하나만 허용하면 안 된다.

## 1. 장비 설정 탭

실제 주소/계정 입력을 받지 않는다. Public Demo에서는 비식별 Demo topology를 보여준다.

표시:
- MM Primary/Standby
- MD 목록
- 세션 조회 주기
- 위치 재확인 주기
- Close-after-misses

"실제 장비 연결 비활성 / 합성 Transport"를 명확히 표시한다.

## 2. 세션 조회 탭

실제 UI와 유사한 입력:
- 출발지 IP
- 목적지 IP
- Source Port (선택)
- Destination Port (선택)
- 양방향 조회

버튼:
- 현재 조회
- 지속 모니터링 시작
- 다음 Poll
- 중지
- Demo Reset

### 현재 조회

UI 입력으로 production `QueryRequest`를 생성한다.

결과 trace:
1. QueryRequest 검증
2. MM 위치 조회
3. Current Switch 확인
4. 등록 MD 매핑
5. 필터형 datapath query
6. Parser
7. QueryOutcome

결과:
- Used MM
- Source/Destination location
- 조회 Controller
- authoritative 여부
- 세션 수
- diagnostics

### 지속 모니터링

production `MonitorEngine`을 사용해 Poll 간 상태가 유지되도록 한다.

Demo timeline 예:
- Poll 1 STARTED/OBSERVED
- Poll 2 OBSERVED + Counter change
- Poll 3 Controller 이동/overlap
- Poll 4 authoritative MISS 1
- Poll 5 MISS 2 + MM refresh
- Poll 6 재관측 또는 MISS
- 설정된 close-after-misses 충족 시 CLOSED
- 중간 Collection Failure poll은 비권위로 처리되어 MISS/CLOSED를 진행시키지 않음

Streamlit에서 실제 background daemon을 지속 실행할 필요는 없다. `다음 Poll` 방식으로도 production MonitorEngine state가 유지되면 충분하다.

## 3. 결과 화면

요약:
- 운영 상태
- Active Sessions
- Used MM
- Controllers
- Authoritative
- Last Poll
- Retry/Diagnostic 상태

세션 표:
- Source
- Destination
- Protocol
- Source Port
- Destination Port
- Controller
- Packets/Bytes
- Flags
- Lifecycle State
- Last Seen

Filter:
- IP
- Protocol
- Port
- Controller
- Lifecycle

선택 세션 상세:
- session key
- current controller
- first/last seen
- miss count
- Flags 설명
- Raw line

## 4. Raw / Diagnostic

탭 분리:
- 장비 원문
- 진단 이벤트
- 조회 경로

수집 실패를 `No Active Session`으로 표시하지 않는다.

## 5. 기록 및 내보내기

브라우저 session 범위에서 Run History 유지.

- Run ID
- Query 조건
- 시작 시각
- Poll 수
- 마지막 상태
- Session Count
- 오류 코드

CSV export 제공.
가능하면 production HTML report generator를 재사용하여 HTML download 제공한다.

SQLite 영속 DB를 Streamlit Cloud multi-user 상태로 공유하지 않는다. 필요하면 session-local temporary storage/adaptor를 사용한다.

## 코드 구조 권장

현재:
- `portfolio_demo/app.py`
- `portfolio_demo/logic.py`
- `portfolio_demo/demo_data/`

개선:
- `portfolio_demo/app.py`: UI
- `portfolio_demo/runtime.py`: session-local Demo Runtime
- `portfolio_demo/fixture_transport.py`: production SSH interface와 호환되는 합성 transport/factory
- `portfolio_demo/logic.py`: production `TrackerService` / `MonitorEngine` orchestration

중요: production Parser 결과를 직접 만들어 반환하지 말고 가능하면 `TrackerService.query_once()` 경로를 통과시킨다.

## 테스트

1. 출발지 IP만으로 QueryRequest 생성
2. 목적지 IP만으로 QueryRequest 생성
3. 양방향/포트 필터가 실제 결과를 변경
4. MM 위치에 따라 조회 MD가 달라짐
5. 존재하지 않는 Client = 적절한 diagnostic
6. Collection failure = non-authoritative
7. Parsing failure = non-authoritative
8. non-authoritative poll이 MISS/CLOSED를 진행시키지 않음
9. authoritative misses만 close-after-misses 진행
10. Controller 이동을 lifecycle에서 표현
11. CSV/HTML export 생성
12. Reset 시 MonitorEngine 및 history 초기화

## 완료 기준

- 고정 3개 Client만 허용하는 구조 제거
- 실제 QueryRequest 입력 UI 구현
- 현재 조회와 지속 모니터링이 서로 다른 실제 production 경로를 사용
- MM→MD 조회 경로가 화면에 보임
- MonitorEngine 수명주기 이벤트 체험 가능
- Raw/Diagnostics/History/Export 제공
- Streamlit Cloud에서 외부 장비 없이 동작
- 실제 장비/계정/운영정보 미포함
