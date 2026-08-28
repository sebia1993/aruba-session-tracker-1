# Aruba Session Tracker v0.3.1 사전릴리스

이번 버전은 기능을 추가하거나 제거하지 않고 Windows 11에서 장시간
조회·모니터링할 때의 저장, 취소, 종료와 릴리스 안정성을 강화한
유지보수 릴리스입니다. 기존 읽기 전용 명령 allowlist, 정확히 60개인 F12
Inspector 카탈로그, CSV 열과 HTML 보고서 구성, 설정 항목은 그대로입니다.

## 안정성 개선

- 한 poll의 Raw 파일, 관측, 진단과 수명주기 이벤트를 복구 가능한 단일
  batch로 저장합니다. DB 반영 전후에 오류가 나도 시작 시 manifest를
  확인해 미완료 작업을 정리하거나 완료합니다.
- 프로세스 간 run lease로 같은 실행 기록을 다른 프로그램 인스턴스가
  동시에 기록하거나 종료하지 못하게 했습니다. 종료 상태 저장과 lease
  정리가 일부만 끝난 경우에도 안전하게 다시 시도할 수 있습니다.
- 관리 Raw·CSV·HTML은 저장된 크기와 SHA-256을 다시 확인합니다. 삭제는
  확인 화면 이후 파일이 바뀌면 중단하며, 복구 manifest가 관련 없는
  파일을 이동하거나 지우지 못하도록 작업 ID와 경로를 엄격히 묶습니다.
- 설정과 `known_hosts`는 1 MiB 상한으로 한 번 연 파일에서 읽습니다.
  관리 경로의 symbolic link, Windows reparse point와 실행 중 디렉터리
  교체도 fail-closed로 차단합니다.
- 모니터 중지 요청이 진행 중 SSH 작업의 cancellation token까지 전달되고,
  poll 준비·영속화·상태 반영 순서를 분리해 저장 실패 뒤 잘못된 수명주기
  상태가 남지 않도록 했습니다.
- Qt 작업과 호스트 키 승인 요청에 명확한 owner/generation을 부여했습니다.
  창을 닫거나 취소하면 대기 중 승인을 거절하고, 늦게 도착한 성공 신호나
  대화상자가 닫힌 화면을 다시 갱신하지 않습니다.
- CSV 행은 묶음 단위로 읽고 Raw SHA-256은 청크 단위로 계산해 긴 실행의
  순간 메모리 사용량을 제한합니다.

## 검증과 배포

- CI는 전역 line coverage 83% 이상과 `main`, runtime, SSH, monitor,
  tracker, storage, UI 핵심 모듈의 branch coverage 65% 이상을 요구합니다.
- 비식별 fixture로 10,000회 monitor poll과 500회 Qt 작업 수명주기 soak를
  실행해 owner, cancellation과 객체 정리를 확인합니다.
- 버전 릴리스는 workflow 소유 draft에서만 자산을 올리고 GitHub가 보고한
  SHA-256과 인증 재다운로드를 확인한 뒤 공개합니다. 공개 뒤에도 다시
  내려받아 로컬 검증 자산과 비교합니다.
- `continuous` 릴리스는 중단된 draft, 후보·이전 자산을 다음 실행에서
  식별해 정리할 수 있으며, 교체 전 오류는 기존 tag와 자산으로 복구합니다.

## 확인하지 않은 범위

테스트는 비식별 fixture, 메모리 내 SSH fake, offscreen Qt와 패키지 smoke를
사용합니다. 실제 Aruba 7240XM/AOS 장비, 실제 Paramiko/Netmiko loopback
소켓, Python이 없는 clean Windows 11 PC의 장시간 운용, 물리 F12/Fn Lock,
고대비·다중 모니터, Authenticode 서명과 조직 보안 제품 허용은 확인하지
않았습니다. 따라서 v0.3.1은 unsigned Windows x64 사전릴리스이며 현장
확인은 승인된 읽기 전용 계정과 절차로 별도 수행해야 합니다.
