# Aruba Session Tracker v0.6.0 continuous 변경 안내

v0.6.0은 기존 읽기 전용 조회와 저장 경계를 유지하면서 데스크톱 운영 화면과
단일 HTML 조사 보고서의 시각 체계를 전면 개편한 이동형 `continuous`
빌드입니다.

## 변경 사항

- 기존 주요 탭 객체를 유지한 상단 NOC 탐색과 운영 헤더에서 MM·MD 설정 수,
  poll 간격, 최근 관측 시각 및 현재 운영 상태를 확인할 수 있습니다.
- 결과 화면에 현재 표시 결과로 확정적으로 계산한 세션 지표와 선택 세션
  요약을 추가하고, 기존 Raw 및 진단 화면은 `RAW CLI`와 `DIAGNOSTICS`로
  유지합니다.
- HTML 보고서를 조회 흐름, 실행 요약, 최신 표시 세션의 상태 요약, 보고서
  스냅샷에 포함된 저장 사실, 최근 결과와 전체 이력 순서의 밝은 조사 보고서로
  재구성합니다.
- 기존 정확값 필터, 단일 CSP-hash 스크립트, 값 escaping, 외부 리소스 및
  네트워크 접근 금지 계약을 유지합니다.

## 호환성과 검증 범위

- 읽기 전용 명령 allowlist, SSH·parser·수명주기 동작, SQLite schema,
  CSV·Raw 형식과 61개 화면 개선 도우미 ID는 변경하지 않습니다.
- 게시 전 GitHub-hosted Windows x64의 일반 non-soak 검증과 패키지·EXE
  smoke를 요구합니다.
- 이번 작업에서는 fixture-only 20,000 poll 시험을 실행하지 않으며
  `v0.6.0` 태그 또는 변경 불가 버전 릴리스를 만들지 않습니다.
- 실제 Aruba 장비, 회사 네트워크 또는 실제 Windows 11 clean PC에는
  접속하지 않습니다.
- 게시 검증이 성공하면 코드 서명되지 않은 Windows 11 x64 ZIP 하나를 이동형
  `continuous` 사전릴리스로 갱신하며 SHA-256은 검증 후 본문에 추가합니다.
