# Aruba Session Tracker v0.5.8 사전릴리스

v0.5.8은 MD 세션 출력이 정상 완료됐음에도 AOS 8 프롬프트 상태 표식을
인식하지 못해 `MD_PARSE / PARSE_PARTIAL`로 처리되던 문제를 수정합니다.
읽기 전용 명령 제한, 단일 IP 조회, MM 출력 해석, 세션 수명주기와 exact-once
저장 경계는 그대로 유지합니다.

## 변경 사항

- `show datapath session table <IP>` 출력에 `Entries: N` footer가 없는 경우,
  마지막 비어 있지 않은 줄이 검증된 enable 프롬프트 형식과 정확히 일치하면
  완료된 출력으로 인정합니다.
- AOS 8의 `^` 미저장 설정 표식, `*` crash 정보 표식과 `^*` 결합 상태를
  지원합니다. 길이와 문자 집합을 제한한 bare-host 프롬프트도 마지막 줄에서만
  허용합니다.
- 단독 상태 표식, 임의 표식, 잘못된 `*^` 순서, 중복 표식, config-mode
  프롬프트와 후행 텍스트는 계속 거부합니다. 헤더, IPv4 행 스키마, 선언된
  행 수, Raw 크기와 관측 수 안전 상한도 완화하지 않습니다.
- 오프라인 tech-support의 명령 echo와 최종 프롬프트에 같은 상태 표식 계약을
  적용합니다. Netmiko prompt read timeout은 장비 원문을 노출하지 않는 재시도
  가능한 수집 오류로 변환합니다.

## 검증 예정 범위와 배포

- 비식별 fixture와 로컬 parser/orchestration 테스트로 정상 `^`, `*`, `^*`,
  bare-host 프롬프트 및 임의·역순·중복·config·후행 텍스트 거부를 검증할
  예정입니다.
- GitHub-hosted Windows x64 Python 3.13 전체 검증, fixture-only 20,000 poll
  soak, Windows 패키지 빌드와 EXE smoke를 사전릴리스 게시 전에 수행할
  예정입니다. 이 문서에는 아직 성공 결과, workflow 실행 번호, 자산 크기나
  SHA-256을 확정해 기록하지 않습니다.
- 실제 Aruba 장비나 회사 네트워크에는 접속하지 않습니다. 자동 검증은 실제
  7240XM/AOS 출력의 모든 변형, Windows 11 clean PC 장시간 운용, 물리 키보드,
  다중 모니터와 Authenticode 서명을 증명하지 않습니다.
- 게시 검증이 모두 성공한 경우 공개 자산은 코드 서명되지 않은 Windows 11 x64
  ZIP 하나이며, 실제 SHA-256은 생성된 자산을 독립적으로 확인한 뒤 릴리스
  본문에 기록합니다.
