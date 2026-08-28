# Aruba Session Tracker

Windows 11에서 Aruba AOS 8 Mobility Conductor와 7240XM Managed Device(MD)를
읽기 전용으로 조회해 특정 IPv4 흐름의 datapath 세션을 찾고 변화 이력을
로컬에 기록하는 한국어 데스크톱 프로그램입니다.

이 프로그램은 설정 변경 도구가 아닙니다. 실행 가능한 명령은 검증된
필터형 조회 명령으로 제한되며, 필터 구문이 장비에서 거부되어도 전체
세션 테이블 조회로 자동 전환하지 않습니다.

## 지원 범위

- Windows 11 x64, 일반 사용자 권한
- CPython 3.13 x64 개발 환경
- Aruba 7240XM / AOS `8.10.0.10_89128` 기준 파서와 비식별 fixture
- Primary Mobility Conductor, Standby, MD 1대 이상
- IPv4 Source/Destination, 선택적 Source/Destination 포트
- 1회 조회와 지속 모니터링
- 로컬 SQLite 이력, 실행별 Raw TXT, 독립적인 CSV와 HTML 보고서 내보내기
- 실행할 때마다 꺼진 상태로 시작하는 `F12` 정적 UI Inspector

다음은 v0.3.1 범위에 포함되지 않습니다.

- 장비 설정 변경, 사용자 삭제 또는 쓰기 API
- 무필터 `show datapath session table` 실행
- 예약/백그라운드 수집, Windows 서비스
- IPv6, 자격증명 저장, 장비별 개별 계정
- 실제 사내 장비 호환성 또는 Authenticode 서명 보증

## 설치와 실행

### 포터블 ZIP

1. GitHub Releases에서 `ArubaSessionTracker_v0.3.1_windows_x64.zip`과
   같은 이름의 `.sha256` 파일을 함께 받습니다.
2. PowerShell에서 해시를 확인합니다.

   ```powershell
   Get-FileHash -Algorithm SHA256 .\ArubaSessionTracker_v0.3.1_windows_x64.zip
   Get-Content .\ArubaSessionTracker_v0.3.1_windows_x64.zip.sha256
   ```

3. ZIP을 쓰기 가능한 일반 폴더에 풀고 `ArubaSessionTracker.exe`를
   실행합니다. Python과 관리자 권한은 필요하지 않습니다.

`continuous`는 최신 `main`의 자동 검증 결과를 갱신하는 이동형
사전릴리스입니다. 같은 이름의 공개 자산을 먼저 지우지 않고 후보 자산을
올려 검증한 뒤 짧은 draft 전환 동안 tag와 자산을 교체합니다. `v0.3.1`
같은 버전 태그 릴리스는 자동화가 기존 릴리스 덮어쓰기를 거부하는 1회성
사전릴리스입니다. 두 릴리스 모두 ZIP, SHA-256 sidecar, CycloneDX SBOM을
제공합니다.

### 소스 실행

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation `
  --check-build-dependencies -e .
.\.venv\Scripts\python.exe -m aruba_session_tracker
```

## v0.3.1 안정성 설계

v0.3.1은 화면 기능, 명령 allowlist와 보고서 형식을 바꾸지 않는 안정화
릴리스입니다.

- 한 poll의 Raw, 관측, 진단과 수명주기를 하나의 복구 가능한 batch로
  기록하고, 실행별 프로세스 간 lease로 동시 기록과 종료 충돌을 막습니다.
- 시작할 때 중단된 Raw·내보내기·삭제 작업의 manifest를 검증해 복구합니다.
  manifest의 작업 ID, run ID, 대상 경로와 파일 무결성이 맞지 않으면 관련
  없는 파일을 건드리지 않고 중단합니다.
- 설정, `known_hosts`, DB, Raw와 관리 내보내기 루트의 link/reparse point와
  실행 중 교체를 감지합니다. 설정과 `known_hosts`는 1 MiB까지만 읽습니다.
- Raw 해시는 청크 단위, CSV 행은 묶음 단위로 처리해 긴 실행의 순간 메모리
  사용량을 제한합니다.
- 모니터 poll과 Qt 작업은 owner/generation을 확인하고 취소 시 대기 중인
  호스트 키 승인과 늦게 도착한 UI 신호를 안전하게 정리합니다.

## F12 개발자 모드

UI Inspector는 화면 요소의 위치와 고정 식별자를 확인해 개선 요청을 작성할
때 사용하는 로컬 전용 보조 기능입니다. 브라우저 개발자 도구, 명령 콘솔,
REPL 또는 장비 진단 콘솔이 아닙니다.

- 앱은 다시 실행할 때마다 개발자 모드가 꺼진 상태로 시작합니다.
- `Ctrl`, `Shift`, `Alt` 같은 수정키를 누르지 않은 일반 `F12`만 개발자
  모드를 켜거나 끕니다. 자동 반복 키 입력과 수정키 조합은 무시합니다.
- `요소 선택`을 시작한 뒤 마우스로 요소를 가리키면 주황색 테두리로
  선택 후보를 표시합니다. 이 상태에서 발생한 클릭, 더블클릭과 컨텍스트
  메뉴는 실제 조회·저장·내보내기·삭제 동작으로 전달되지 않습니다.
- `Esc`는 현재 요소 선택만 취소하고 개발자 모드는 계속 유지합니다. 다시
  `F12`를 누르면 선택 상태와 표시 UI까지 모두 닫힙니다.
- 선택 결과에서 프로그램 버전, 정적 한국어 이름, 고정 UI ID, 화면 경로,
  저장소 상대 소스 경로와 용도를 확인할 수 있습니다. `복사`는 이 정보와
  비어 있는 `현재 현상`, `원하는 변경` 입력란만 클립보드에 넣습니다.

정적 카탈로그는 공통 영역 7개와 세 화면 전체를 합한 정확히 60개 ID로
구성됩니다.

| 화면 | ID 수 | 포함하는 운영 요소 |
| --- | ---: | --- |
| 공통 | 7 | 주 창, 상태 표시줄, 탭 영역·탭 바와 세 화면 진입점 |
| 세션 조회 | 23 | 자격증명 입력, 조회 조건, 조회·모니터링·중지, 상태·조회 맥락, 결과 표·헤더·본문·선택 항목, 상세 탭, Raw 보기, 진단 목록 |
| 장비 설정 | 20 | MM Primary·Standby 이름/주소/포트/사용 여부, MD 표·헤더·본문·선택 항목, 모니터링 주기·종료 MISS, 설정 저장, 개인정보 안내 |
| 기록 및 내보내기 | 10 | 새로 고침, CSV·HTML 내보내기, 선택·전체 삭제, 실행 표·헤더·본문·선택 항목, 개인정보 안내 |

Inspector는 이 카탈로그에 코드로 등록된 정적 메타데이터만 사용합니다.
카탈로그와 프로그램 버전 외의 런타임 데이터는 읽지 않습니다. 현재 입력된
IP·호스트명·계정·암호·Enable 암호, 장비 정보, 표의 행이나 셀, Raw CLI,
진단·로그, 설정 값 또는 로컬 절대 경로를 읽거나 복사하지 않습니다. 어떤
정보도 외부로 보내지 않으며 활성 상태를 CLI 인자, 환경변수,
`config.json`, Windows 레지스트리 또는 SQLite에 저장하지 않습니다.

복사한 요청 양식을 붙여 넣은 문서에는 이후 사용자가 작성한 내용이
남습니다. 외부 이슈나 지원 채널에 보내기 전에는 실제 네트워크 정보,
계정 또는 다른 민감정보를 직접 추가하지 않았는지 확인하십시오.

## 처음 설정

설정 화면에서 다음 비밀이 아닌 연결 정보만 등록합니다.

- Primary Conductor 이름, IPv4, SSH 포트
- Standby 이름, IPv4, SSH 포트
- MD 이름, IPv4, SSH 포트, 활성 여부
- 세션 조회 주기, MM 위치 재확인 주기, 종료 판정 MISS 횟수

공통 사용자 ID, 암호와 선택적 Enable 암호는 실행 중 메모리에만 있으며
`config.json`, SQLite, 로그 또는 릴리스 파일에 저장되지 않습니다. 앱의
비밀이 아닌 설정 예시는 [config.example.json](config.example.json)에
RFC 5737 문서용 주소로만 제공됩니다.

첫 SSH 접속에서는 장비 지문을 검토한 뒤 승인해야 합니다. 승인된 지문이
나중에 바뀌면 연결을 차단합니다. 인증 실패와 호스트 키 불일치는
Standby 우회 조건이 아닙니다.

## 조회 흐름

1. Source IPv4와 Destination IPv4를 입력합니다.
2. 필요한 경우 SPort와 DPort를 입력합니다. 포트를 비우면 해당 방향의
   포트는 필터 조건에서 제외됩니다.
3. 기본으로 켜진 `양방향`은 역방향을 확인할 때 IP와 포트를 함께
   교환합니다. 표시되는 관측 데이터의 실제 방향은 바꾸지 않습니다.
4. 프로그램이 Source의 Current switch를 MM에서 확인하고 매핑된 MD에
   필터형 datapath 명령을 보냅니다.
5. 첫 MD에 일치 행이 없고 Destination이 다른 MD에 있으면 그 MD 한 대를
   추가 조회합니다.
6. 두 IP 모두 MM에 없을 때만 경고와 매회 승인을 거쳐 활성 MD를
   순차적으로 조회할 수 있습니다.

프로그램의 장비 명령 allowlist는 다음과 같습니다.

```text
show global-user-table list ip "<IPv4>"
no paging
show datapath session table <IPv4>
```

필터 명령이 거부되면 `COMMAND_VARIANT_UNVERIFIED`로 중단합니다. 명령
문자열에는 검증을 통과한 IPv4만 들어가므로 임의 CLI 조각을 입력할 수
없습니다.

## 지속 모니터링과 화면 의미

기본값은 MD 세션 5초, MM 위치 30초, 총 3회 MISS 후 `CLOSED`입니다.
2회 연속 MISS가 발생하면 정기 주기를 기다리지 않고 MM 위치를 다시
확인합니다. 같은 5-tuple이 종료 뒤 다시 나타나면 새 세션 인스턴스로
기록합니다.

결과에는 사용한 MM/MD, 마지막 관측 시각, Protocol, Source/Destination,
포트, Packets/Bytes와 증분, Age, CPU, Raw Flags, 해석 상태가 표시됩니다.
세션 키는 `Controller + Protocol + SRC + DST + SPort + DPort`이며 Flags는
키에 포함되지 않고 변화 이벤트로 남습니다.

Flags는 [HPE Aruba AOS 8 datapath 명령 문서](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/sh-datapath.htm)에
공식적으로 정의된 문자만 해석합니다. 예를 들어 `D`는 deny, `Y`는 no
SYN, `R`은 redirect입니다. 정의를 확인하지 못한 문자는
`UNKNOWN/CHECK`로 표시하며 장애로 단정하지 않습니다. MM 위치 파싱은
[global-user-table 명령 문서](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/sh-glb-usr-tab.htm)의
출력 구조를 기준으로 합니다.

## HTML 결과 보고서

`기록 및 내보내기` 화면에서 종료된 실행을 선택하면 기존 CSV와 별도로
`선택 실행 HTML 보고서`를 사용할 수 있습니다. CSV는 전체 관측 행을
분석하는 데이터 파일이고, HTML은 사람이 실행 결과와 주의사항을 빠르게
검토하는 기술문서입니다. 두 경로는 서로 독립적이며 하나를 만들지 않아도
다른 하나를 계속 사용할 수 있습니다.

HTML 보고서는 다음 조건을 만족합니다.

- 단일 UTF-8 HTML5 파일, 내장 CSS, 외부 CSS/JavaScript/CDN/웹폰트 없음
- PC·태블릿·모바일 반응형, Sticky 목차, 가로 스크롤 표, 인쇄 스타일
- 지원 기준 환경, 실행 조건, Executive Summary와 프로그램 조회 흐름
- 최신 고유 세션, Raw Flags 해석, 수명주기와 Controller 전환
- 비식별 진단, Troubleshooting, Warning, 수집 파일 크기·SHA-256
- 허용된 읽기 전용 CLI의 명령어·목적·예상 결과와 Quick Reference

보고서는 선택한 실행의 SQLite 스냅샷만 사용합니다. 실행 당시 저장되지
않은 VLAN, SSID, Role, ACL, 인터페이스, 물리 토폴로지나 실제 장비에서
검출한 모델/펌웨어는 만들지 않고 `확인 필요`로 표시합니다. Raw CLI 본문과
자격증명은 넣지 않으며 모든 저장 문자열은 HTML 이스케이프합니다. 긴
모니터링 결과는 표시 상한과 전체 건수를 함께 알리고 전체 행은 CSV 또는
SQLite에서 확인하도록 안내합니다.

HTML은 인터넷 연결 없이 Edge/Chrome에서 직접 열 수 있습니다. 내부 IP,
장비명과 세션 메타데이터는 결과 자체이므로 평문으로 포함될 수 있습니다.
외부에 공유하기 전에는 HTML 원문을 열어 민감정보를 직접 제거하고
검토하십시오.

## 로컬 데이터와 개인정보

기본 저장 위치는 `%LOCALAPPDATA%\ArubaSessionTracker`입니다.

```text
config.json        비밀이 아닌 장비/주기 설정
known_hosts        승인한 SSH 호스트 키
tracker.db         실행, 관측, 수명주기, 전환, 비식별 진단 이벤트
.operations\       장애 복구 manifest와 프로세스 간 lease
raw\<run-id>\      실행별 UTF-8 장비 원문
exports\           사용자가 명시적으로 만든 CSV/HTML 내보내기
```

`.operations`에는 작업 ID, 상대 경로, 크기와 SHA-256 등 복구 메타데이터만
기록하며 자격증명이나 Raw CLI 본문은 넣지 않습니다. Raw 파일은 SQLite에
상대 경로, 바이트 크기, SHA-256으로 연결됩니다.
일반 진단 메시지에서는 IPv4와 자격증명 형태를 마스킹합니다. CSV의
문자열은 Excel 수식 삽입을 막도록 보호하고 HTML의 저장 값은 태그나
스크립트로 실행되지 않도록 이스케이프합니다.

기록은 자동 삭제하지 않습니다. 삭제 화면은 실행 수, DB 행 수, Raw와
관리 내보내기 파일 수·전체 크기를 먼저 보여주고 사용자가 확인한 경우에만
5분짜리 1회용 미리보기에 포함된 항목을 삭제합니다. 미리보기 뒤 데이터가
달라지거나 관리 루트 밖을 가리키는 경로가 있으면 삭제하지 않습니다.
사용자가 다른 폴더를 직접 선택해 내보낸 CSV와 HTML은 자동 삭제 대상이
아닙니다.

Raw, DB, 내보낸 CSV와 HTML에는 실제 네트워크 정보가 포함될 수 있습니다.
GitHub 이슈나 외부 지원 채널에 올리지 말고, 공유가 필요하면 IP, 장비명,
계정, 명령 출력을 제거한 오류 코드와 단계만 제공하십시오.

## 주요 오류 코드

| 코드 | 의미 |
| --- | --- |
| `AUTH_FAILED` | SSH 인증 실패이며 자동 우회하지 않음 |
| `HOST_KEY_UNKNOWN` | 아직 승인하지 않은 SSH 지문 |
| `HOST_KEY_CHANGED` | 승인 뒤 지문이 달라져 연결 차단 |
| `MM_UNREACHABLE` | MM 네트워크 연결 또는 시간 초과 |
| `MD_UNREACHABLE` | MD 네트워크 연결 또는 시간 초과 |
| `CURRENT_SWITCH_UNMAPPED` | Current switch를 등록된 MD와 매핑할 수 없음 |
| `COMMAND_VARIANT_UNVERIFIED` | 필터형 명령 구문을 장비가 거부함 |
| `PARSE_PARTIAL` | 일부 출력만 안전하게 해석됨 |

오류는 장비 장애의 증거가 아닙니다. 특히 parser/SSH 실패와 빈 결과를
세션 종료 또는 장비 다운으로 단정하지 마십시오.

## 개발과 검증

저장소는 네트워크와 분리된 비식별 fixture 및 메모리 내 SSH 프로토콜
fake를 기본 검증 경계로 사용합니다. 실제 소켓을 여는 Paramiko/Netmiko
loopback 통합시험은 v0.3.1에 포함되지 않습니다.

```powershell
.\tools\validate.ps1 -PythonPath .\.venv\Scripts\python.exe
.\build_windows.ps1 -PythonPath .\.venv\Scripts\python.exe -Version 0.3.1
```

`validate.ps1`은 Python/아키텍처, 해시 고정 lock 동기화, 의존성, 버전
동기화, 비밀/런타임 파일, Ruff, 포맷, strict mypy, pytest/branch coverage,
전역 line 83%·핵심 모듈 branch 65% 정책과 runtime 및 build/development
의존성 `pip-audit`를 확인합니다.
`build_windows.ps1`은 깨끗한 Git 커밋에서 PyInstaller onedir ZIP을 만들고
문서, commit이 결합된 `BUILD_INFO.json`, 전체 runtime lock 기반 SBOM을
포함한 뒤 private/runtime 파일 부재, SHA-256, Windows EXE logic/native
Qt GUI smoke를 검증합니다. 로컬 시험용 dirty build만
`-AllowDirty`를 명시할 수 있으며 릴리스에는 사용할 수 없습니다.

Windows 11 현장 UI 확인에서는 실제 키보드의 `F12`와 Fn Lock 조합, 다른
입력란에 포커스가 있을 때의 전환, 재시작 후 OFF 상태, 클립보드 복사,
100%·125%·150% 배율, 고대비 테마와 다중 모니터 배치를 별도로 확인해야
합니다. 자동화된 offscreen GUI smoke는 이 물리 환경 확인을 대신하지
않습니다.

PR과 `main`은 GitHub-hosted Windows x64 CI를 통과해야 합니다. `main`
변경은 현재 main과 빌드 commit을 다시 비교한 뒤 기존 release를 지우지
않고 `continuous` tag, 메타데이터와 자산을 갱신합니다.
`vMAJOR.MINOR.PATCH`는 반드시 annotated tag여야 하며 원격 tag, checkout
HEAD, GitHub event SHA, 최신 원격 `main`이 같은 commit일 때만 변경 불가
정책의 사전릴리스를 처음 한 번 게시합니다. 이 불변성은 release workflow
정책이며, 저장소 관리자 권한 자체를 제거하지는 않습니다. GitHub의
저장소 전체 immutable release 설정은 이동형 `continuous`도 함께
고정하므로 이 저장소에서는 사용하지 않습니다.

## 검증 증거의 한계

fixture 테스트, 메모리 내 protocol fake, GitHub-hosted Windows CI, EXE
smoke와 패키지 검증은 다음을 증명하지 않습니다.

- 실제 Aruba 7240XM/AOS 현장 출력과의 완전한 호환성
- 실제 Windows 11 clean PC 또는 Python 미설치 사내 PC에서의 장시간 운용
- 실제 SSH 소켓의 banner/prompt/paging/timeout 상호작용
- Authenticode 서명 또는 조직 보안 제품의 허용
- 실장비 네트워크 상태나 세션 존재/종료

v0.3.1은 이 한계를 명시한 unsigned 사전릴리스입니다. 현장 검증은
읽기 전용 계정과 승인된 변경 절차로 별도 수행해야 합니다.

라이선스는 MIT이며 제3자 구성요소 고지는
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)를 참고하십시오.
