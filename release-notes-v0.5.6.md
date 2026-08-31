# Aruba Session Tracker v0.5.6 사전릴리스

v0.5.6은 v0.5.5의 읽기 전용 명령 제한, 단일 IP 조회, MM 출력 해석과 저장
형식을 유지하면서 잘못된 장비 토폴로지를 실행 전에 차단하고 poll 저장의
exact-once 경계를 강화합니다.

## 변경 사항

- 활성 Primary/Standby MM이 같은 주소와 포트를 사용하거나 활성 MD 사이에
  주소·정규화 이름·Current switch 별칭 충돌이 있으면 `AppConfig` 생성 단계에서
  중단합니다. 비활성 장비 placeholder는 기존 구성과 loopback 검증 호환성을
  위해 충돌 검사에서 제외합니다.
- SQLite schema v3의 `poll_commits`에 poll ID, 실행 ID와 payload SHA-256을 같은
  transaction의 마지막 durable receipt로 저장합니다. 같은 ID와 같은 내용의
  재시도는 기존 commit을 확인해 관측·진단·수명주기 이벤트와 Raw 연결을 다시
  삽입하지 않습니다. 다른 실행이나 다른 내용에 같은 ID를 사용하면 거부합니다.
- DB commit 뒤 manifest·staging·lease 정리가 실패해도 poll을 저장 실패로
  되돌리거나 모니터링 상태를 폐기하지 않고 `COMMITTED_RECOVERY_PENDING`으로
  구분합니다. 같은 poll ID 재시도나 다음 시작 복구가 receipt와 payload·Raw
  무결성을 확인한 뒤 남은 파일 작업을 마칩니다. 불확정 poll 재확인 중 추가
  저장 오류나 동시 중지가 발생해도 준비 상태와 ID를 보존하고, 확인된 commit만
  모니터 상태에 반영합니다. 실패했던 실행 종료 기록의 동시 재시도도 직렬화해
  완료된 run을 다시 보류하지 않습니다.
- SQLite writer가 `BUSY` 또는 `LOCKED`를 반환한 경우에만 짧고 제한된 재시도를
  수행합니다. commit 응답이 불명확하면 receipt를 다시 확인하고, receipt도
  읽을 수 없으면 새 poll로 추측해 다시 쓰지 않고 동일 poll ID 복구가 필요한
  상태로 중단합니다.
- 시작 복구는 delete manifest를 Raw batch manifest보다 먼저 처리합니다. 삭제
  staging으로 잠시 이동한 정상 Raw를 누락 또는 손상으로 오판하지 않으며,
  작업 lease 제거 실패 시에는 manifest를 다음 복구의 anchor로 남깁니다.

## 검증 예정 범위와 배포

- 비식별 fixture와 메모리 내 SSH fake를 사용해 토폴로지 충돌, schema v2에서
  v3 migration, 동일 poll 재시도, commit 응답 불명확, cleanup pending과
  delete/Raw 시작 복구 순서를 회귀 검증할 예정입니다.
- GitHub-hosted Windows x64의 Python 3.13 전체 검증, fixture-only 20,000 poll
  soak, Windows 패키지 빌드와 EXE smoke를 사전릴리스 게시 전 수행할
  예정입니다. 이 문서에는 아직 성공 결과, workflow 실행 번호, 자산 크기나
  SHA-256을 확정해 기록하지 않습니다.
- 실제 Aruba 장비나 회사 네트워크에는 접속하지 않습니다. 자동 검증은 실제
  7240XM/AOS 현장 출력의 모든 변형, 물리적 전원 차단의 파일 시스템 내구성,
  Windows 11 clean PC 장시간 운용이나 Authenticode 서명을 증명하지 않습니다.
- 게시 검증이 모두 성공한 경우 공개 자산은 코드 서명되지 않은 Windows 11 x64
  ZIP 하나이며, 실제 SHA-256은 생성된 자산을 독립적으로 확인한 뒤 릴리스
  본문에 기록합니다.
