# Aruba Session Tracker v0.5.5 사전릴리스

v0.5.5는 v0.5.4의 읽기 전용 명령 제한, 단일 IP 조회, 저장 형식과 장시간
안정성 경계를 유지하면서 AOS 8 MM의 가운데 정렬된 global-user 출력을
안전하게 해석합니다.

## 변경 사항

- `show global-user-table list ip` 헤더 라벨의 글자 위치가 아니라 열별 대시
  구분선의 시작 위치를 사용합니다. IP와 MAC 헤더가 가운데 정렬되고 Name과
  Auth가 비어 있어도 Client IP와 Current switch를 정확히 분리합니다.
- 출발지 IP만, 목적지 IP만 또는 두 IP를 모두 입력한 조회에 같은 파서를
  적용합니다. 두 IP가 서로 다른 MD에 있어도 각 Current switch를 확인한 뒤
  기존 필터형 datapath 명령만 실행합니다.
- 헤더와 구분선이 일치하지 않거나 헤더 연속 줄이 역순·중복인 출력은
  `PARSE_PARTIAL`로 처리하고 MD 조회 전에 중단합니다. 임의의 IPv4 토큰을
  Current switch로 추정하거나 무필터 세션 명령으로 전환하지 않습니다.
- 기존 좌측 정렬 헤더와 단일 연속 구분선 출력은 헤더가 열 시작에서 시작하는
  경우에만 제한적으로 계속 지원합니다.

## 검증 범위와 배포

- HPE 문서 형태의 열 간격을 RFC 5737 문서용 IPv4와 예약 문서용 MAC으로
  재현한 fixture에서 빈 Name/Auth, AP MAC, populated Name, 구형 출력과
  비정상 열 경계를 검사합니다.
- 서비스 회귀 시험은 출발지 단독과 두 IP 조회의 위치 해석, 서로 다른 MD
  라우팅, 목적지 파싱 실패 시 MD를 한 대도 조회하지 않는 경계를 확인합니다.
- 실제 Aruba 장비나 회사 네트워크에는 접속하지 않습니다. GitHub-hosted
  Windows x64에서 Python 3.13 검증, 패키지 빌드와 EXE smoke를 수행합니다.
- 공개 자산은 코드 서명되지 않은 Windows 11 x64 ZIP 하나이며 SHA-256은
  릴리스 본문에 기록합니다. 자동 테스트는 실제 현장 출력의 모든 변형이나
  Authenticode 서명을 증명하지 않습니다.
