# Aruba Session Tracker v0.5.1 사전릴리스

v0.5.1은 v0.5.0의 단순한 조회 화면, 프로토콜·출발지·목적지 `IP:포트`
중심 HTML 결과 보고서와 저장 형식을 그대로 유지하는 안정성 패치입니다.

## 변경 사항

- Windows 타이머가 poll 마감 직전에 조금 일찍 깨어나도 실제 단조 시계의
  마감 시각을 다시 확인합니다. SSH 연결 manager와 연결 수립용 socket
  감시기가 같은 정책을 사용하므로, 이미 중단된 연결을 성공으로 반환하거나
  시간 초과를 다른 네트워크 오류로 잘못 분류하는 경계를 막았습니다.
- 버전 릴리스 게시 작업이 고정된 runtime 의존성과 `pip check`를 먼저
  통과한 뒤 Windows ZIP을 다시 검증하도록 보완했습니다.
- 지연된 Qt 창 닫기 콜백을 해당 창의 수명에 연결하고, 종료 중 daemon 작업의
  늦은 완료 신호를 안전하게 무시해 다음 화면 처리에서 삭제된 창을 다시
  호출하지 않도록 했습니다.
- 시작 직후 백그라운드 저장소 대조와 상태 확인이 겹쳐 SQLite WAL이 정상
  삭제되는 순간을 저장 실패로 오인하던 Windows 파일 수명 경합을 수정했습니다.
  link·reparse·일반 파일 검사는 동일한 단일 파일 상태에서 계속 수행합니다.
- PR 2,000회 및 야간 20,000회 가상 soak의 child-process 제한을 느린
  GitHub Windows 디스크 변동과 workflow 전체 120분 제한에 맞췄습니다.
  무한 대기는 허용하지 않습니다.

## 호환성과 검증 범위

- 기존 설정, SQLite DB, CSV, HTML과 Raw 형식은 변경하지 않았습니다.
- 비식별 parser fixture, 수집기 fake, 127.0.0.1 loopback SSH 서버, 임시
  SQLite/Raw 저장소, 장애 주입, 가상 장시간 조회와 Windows x64 패키지
  smoke로 검증합니다.
- Qt 지연 닫기 수명 회귀, 종료 후 늦은 worker 신호, SQLite WAL 소멸 경합을
  결정적 장애 주입과 반복 테스트로 별도 검증합니다.
- 실제 Aruba 장비나 회사 네트워크에는 접속하지 않았습니다. 자동·가상·패키지
  결과는 현장 호환성, 실제 장시간 운용 또는 Authenticode 서명을 증명하지
  않습니다.
- 공개 자산은 unsigned Windows 11 x64 ZIP 하나입니다. SHA-256은 릴리스
  본문에 추가되고 CycloneDX SBOM은 ZIP 내부에 포함됩니다.
