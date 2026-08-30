# Aruba Session Tracker v0.5.2 사전릴리스

v0.5.2는 v0.5.1의 읽기 전용 조회, 로컬 기록과 결과 보고서 형식을 유지하면서
외부 보고서 복구 안내와 릴리스 검증 경계를 보강한 안정성 패치입니다.

## 변경 사항

- 외부 USB 드라이브가 분리되거나 UNC 공유를 사용할 수 없어도 앱은
  정상적으로 시작하며 해당 외부 복구 건만 보류한다고 안내하도록
  개선했습니다. 저장 위치를 다시 사용할 수 있게 한 뒤 기록을 새로 고치면
  복구를 다시 시도합니다.
- CSV와 HTML 각각 `PREPARED`, `RENDERED`, `INSTALLED`,
  `DB_RECEIPT_COMMITTED`, `DB_COMMITTED`에서 저장 위치가 분리되는 10개 조합을
  회귀 시험해, 재연결 뒤 완료 증표 전에는 기존 파일을 복원하고 완료 증표
  후에는 새 파일을 유지하는지 검증합니다.
- 이동형 `continuous` 사전릴리스의 독립 게시 runner도 고정 runtime lock을
  설치하고 `pip check`를 통과한 뒤 검증 도구를 실행하도록 보완했습니다.
- 버전 릴리스는 exact annotated-tag commit에서 별도 120분 제한의
  20,000-poll fixture-only soak를 통과하고 패키지 build도 성공한 뒤에만
  게시하도록 강화했습니다.

## 호환성과 검증 범위

- 기존 설정, SQLite DB, CSV, HTML과 Raw 형식은 변경하지 않았습니다.
- 비식별 fixture, 로컬 fake, 임시 저장소, 장애 주입, CSV·HTML 외부 복구
  10개 조합과 가상 장시간 시험으로 검증합니다.
- 실제 Aruba 장비나 회사 네트워크에는 접속하지 않았습니다. 자동·가상·패키지
  결과는 현장 호환성, 실제 장시간 운용 또는 Authenticode 서명을 증명하지
  않습니다.
- 공개 자산은 unsigned Windows 11 x64 ZIP 하나입니다. SHA-256은 릴리스
  본문에 추가되고 CycloneDX SBOM은 ZIP 내부에 포함됩니다.
