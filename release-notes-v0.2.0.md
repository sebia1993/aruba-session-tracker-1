# Aruba Session Tracker v0.2.0 사전릴리스

기존 Aruba 세션 조회·모니터링과 CSV 내보내기를 유지하면서, 선택한 실행
기록을 네트워크 엔지니어가 브라우저에서 바로 검토할 수 있는 독립형 HTML
결과 보고서로 내보낼 수 있습니다.

## 새 기능

- 기록 화면의 별도 `선택 실행 HTML 보고서` 기능
- 단일 UTF-8 HTML5 파일과 내장 CSS로 완전한 오프라인 실행
- PC, 태블릿, 모바일 반응형 레이아웃과 인쇄 전용 스타일
- 실행 환경·조회 조건·Executive Summary와 프로그램 조회 흐름
- 최신 세션, Raw Flags 공식 해석, 수명주기와 Controller 전환 타임라인
- 비식별 진단 기반 Troubleshooting, Warning, CLI Quick Reference
- Raw 파일의 크기·SHA-256 수집 증거 제공

## 안전 경계

- 기존 CSV 내보내기는 독립적으로 계속 사용할 수 있습니다.
- HTML에는 Raw CLI 본문, 자격증명 또는 현재 설정 화면 값을 넣지 않습니다.
- DB와 장비에서 온 문자열은 HTML 이스케이프하며 외부 CSS, JavaScript,
  웹폰트, CDN과 원격 이미지를 사용하지 않습니다.
- 저장되지 않은 VLAN, SSID, Role, ACL, 인터페이스와 물리 토폴로지는
  추측하지 않고 `확인 필요`로 표시합니다.
- HTML에는 내부 IP, 장비명과 세션 메타데이터가 포함될 수 있으므로 외부
  공유 전 사용자가 원문을 검토하고 민감정보를 제거해야 합니다.
- 실제 생성 보고서는 Git, CI 산출물과 공개 릴리스 ZIP에 포함되지 않도록
  검증기가 차단합니다.

## 검증 한계

비식별 fixture, 메모리 내 protocol fake, HTML 구조·저장 XSS·오프라인
검사, Windows 패키지 보고서/GUI smoke는 실제 Aruba 장비, 사내 데이터,
장시간 현장 운용 또는 Authenticode 서명을 증명하지 않습니다. 현장 확인은
승인된 읽기 전용 절차로 별도 수행하십시오.
