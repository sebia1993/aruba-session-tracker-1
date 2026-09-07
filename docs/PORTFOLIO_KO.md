# Aruba 세션 추적: 운영 문제와 구현 근거

특정 IPv4 통신을 조사할 때 단말의 현재 MD를 찾고 datapath 세션을 반복 조회해야 합니다. 이 프로젝트는 위치 확인 → 필터형 조회 → 파싱 → 관측 이력 저장을 연결하며, 수집 실패와 실제로 관찰하지 못한 세션을 구분합니다.

## 사례: 단말이 MD 사이를 이동하는 동안 조회가 실패할 때

- 출발지와 목적지가 다른 MD에 있으면 두 MD를 조회 범위에 포함합니다.
- 같은 5-tuple이 여러 MD에서 동시에 보이면 하나의 논리 수명주기에 MD별 관측과 Raw 근거를 보존합니다.
- 한 MD의 성공 결과만으로 다른 MD의 흐름을 `MISSED` 또는 `CLOSED`로 진행시키지 않습니다.
- SSH·파싱·부분 수집 실패는 비권위 결과로 남기며, 온전한 후속 관측으로 확인될 때 상태를 갱신합니다.

세션 관찰이 애플리케이션 성공이나 패킷 전달 완료를 증명하지는 않습니다. 장비 Flags 해석, 세션 수명주기, 장애 원인 판단은 서로 다른 의미입니다.

## 설계 판단에서 구현까지

| 판단 | 구현 | 검토할 회귀 근거 |
|---|---|---|
| 사용자 입력을 임의 CLI로 연결하지 않음 | [commands.py](../src/aruba_session_tracker/commands.py): IPv4 검증 후 고정 조회 구문 생성 | [test_commands.py](../tests/test_commands.py) |
| 잘린 출력·중복 세션 키를 정상 전체 결과로 수용하지 않음 | [datapath parser](../src/aruba_session_tracker/parsers/datapath.py), [tracker service](../src/aruba_session_tracker/services/tracker.py) | [parser tests](../tests/test_parsers.py), `test_duplicate_session_key_is_non_authoritative_and_preserves_raw` in [tracker tests](../tests/test_tracker_service.py) |
| 수집 실패와 실제 미관측을 분리 | [monitoring.py](../src/aruba_session_tracker/services/monitoring.py) | `test_non_authoritative_poll_never_advances_miss_or_closes`, `test_monitor_defers_controller_change_across_authoritative_overlap` in [tracker tests](../tests/test_tracker_service.py) |
| 장기 조회 중 자원·저장 수명주기를 제한 | [SSH collector](../src/aruba_session_tracker/collectors/ssh.py), [session store](../src/aruba_session_tracker/storage/session_store.py) | [fixture soak](../tests/test_end_to_end_soak.py), [storage tests](../tests/test_storage.py) |
| 결과를 재검토할 수 있도록 원문과 이력을 보존 | [Raw 관리](../src/aruba_session_tracker/storage/raw.py), [HTML 보고서](../src/aruba_session_tracker/storage/html_report.py) | [HTML tests](../tests/test_html_report.py), [Windows 파일 식별 tests](../tests/test_windows_file_metadata.py) |

## 장비 없이 재현하기

Windows x64·CPython 3.13에서 저장소 루트의 개발 환경을 준비합니다. 의존성 설치는 개발 환경 통신이며, 아래 테스트는 비식별 fixture와 local fake를 사용합니다.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation --check-build-dependencies -e .
.\.venv\Scripts\python.exe -m pytest -q tests/test_commands.py tests/test_parsers.py tests/test_tracker_service.py
```

기대 결과는 세 테스트 파일의 통과입니다. 입력 거부·불완전 파싱·MD 중첩·비권위 결과 처리를 확인하며 실제 장비 자격 증명은 필요하지 않습니다.

전체 검증은 다음의 기존 경로를 사용합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\validate.ps1
```

[CI 구성](../.github/workflows/ci.yml)은 검증 후 Windows onedir 패키지를 만들고 추출 EXE를 검사합니다. [릴리스 workflow](../.github/workflows/release.yml)의 20,000-poll fixture soak는 별도 검증이며, 짧은 회귀 실행이나 macOS 테스트로 대체 완료를 주장하지 않습니다.

## 증거 해석과 한계

- [Windows CI 실행](https://github.com/sebia1993/aruba-session-tracker-1/actions/workflows/ci.yml)에서 대상 SHA·검사·패키지 결과를 확인합니다.
- [continuous](https://github.com/sebia1993/aruba-session-tracker-1/releases/tag/continuous)는 이동형 사전릴리스입니다. 파일명 버전만으로 immutable 태그 발행을 추정하지 않습니다.
- 공개 fixtures는 AOS `8.10.0.10_89128` 기준입니다. 다른 AOS 출력과 실제 장비 호환성은 별도 확인해야 합니다.
- 실제 Aruba 접속, 인증 정책, 장시간 운영망 부하, 회사 PC의 EDR/GPO·SmartScreen은 fixture·loopback 검증과 다릅니다.
- Raw·SQLite·CSV·HTML은 운영 데이터가 될 수 있으므로 실제 결과를 공개 예제로 넣지 않습니다. 세션 자격 증명은 메모리에만 유지합니다.
- 포트폴리오로 설명할 수 있는 결과는 코드·회귀·배포 절차이며, 장애 감소율·조사 시간 절감·운영 도입 규모는 별도의 측정 증거가 필요합니다.
