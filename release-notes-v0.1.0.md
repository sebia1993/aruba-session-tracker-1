# Aruba Session Tracker v0.1.0 사전릴리스

Windows 11 x64에서 Aruba AOS 8 Mobility Conductor와 7240XM Managed Device의
세션을 읽기 전용으로 추적하는 최초 검증판입니다.

## 포함 내용

- Source/Destination IPv4와 선택 포트 기반 양방향 검색
- Primary/Standby MM 위치 조회와 등록 MD 매핑
- 필터형 datapath 세션 조회, 1회 조회와 지속 모니터링
- 세션 변화/종료, Controller 전환, 비식별 진단 이벤트의 SQLite 기록
- 실행별 UTF-8 Raw TXT와 SHA-256 연결
- UTF-8 BOM CSV와 Excel 수식 삽입 방어
- SSH 지문 승인 및 변경 차단, 세션 한정 자격증명
- Python이 필요 없는 PyInstaller onedir Windows x64 ZIP
- SHA-256 sidecar와 전체 runtime hash lock 기반 CycloneDX SBOM

## 안전 경계

- 설정 변경 명령과 무필터 전체 세션 테이블 조회는 실행하지 않습니다.
- 인증 실패와 호스트 키 불일치는 Standby로 우회하지 않습니다.
- 실제 설정, 자격증명, DB, Raw, CSV, 로그, known_hosts는 릴리스 ZIP에
  포함되지 않도록 패키지 검증기가 차단합니다.
- 이 사전릴리스는 Authenticode 서명되지 않았습니다.

## 검증 한계

비식별 fixture, 메모리 내 protocol fake, GitHub-hosted Windows CI, 패키지
무결성 및 EXE smoke 검증은 실제 SSH 소켓, Aruba 7240XM/AOS 장비 호환성,
Windows 11 clean PC 또는 사내 PC 장시간 운용을 증명하지 않습니다. 현장
확인은 승인된 읽기 전용 절차로 별도 수행하십시오.
