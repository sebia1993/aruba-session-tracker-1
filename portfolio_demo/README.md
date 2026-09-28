# Aruba Datapath Session Tracker — Public Demo

**[Live Demo](https://sebia1993-session-tracker-demo.streamlit.app/)** · [GitHub Source](https://github.com/sebia1993/aruba-session-tracker-1)

## 무엇을 보여주는 데모인가

무선 단말 IP를 입력하면 **어느 Controller에 연결되어 있는지 찾고, 그 Controller에서 해당 단말의 datapath 통신 세션을 조회하는 장애 분석 도구**입니다.

대표적인 사용 상황은 다음과 같습니다.

> “Wi-Fi 연결은 정상인데 특정 서버 접속이 안 됩니다.”

기존에는 MM에서 단말 위치를 찾고, 관련 MD로 이동해 다시 datapath session 명령을 실행해야 합니다. 이 도구는 그 흐름을 하나의 조회로 연결합니다.

## 가장 빠르게 보는 방법

1. Live Demo를 엽니다.
2. **샘플 세션 조회 1-click**을 누릅니다.
3. 상단의 자연어 **결론**에서 어느 Controller에서 몇 개 세션이 확인됐는지 봅니다.
4. `세션 Console`에서 Source → Controller → Destination 흐름과 세션 상세를 확인합니다.
5. 필요할 때만 `Advanced Diagnostics`에서 Raw CLI와 진단 이벤트를 봅니다.

## 용어

- **MM (Mobility Conductor / Master)**: 단말이 어느 Controller에 있는지 확인하는 상위 관리 계층
- **MD (Managed Device / Controller)**: 실제 무선 트래픽을 처리하며 datapath session을 조회하는 장비
- **datapath session**: 단말 IP·포트·프로토콜 기준으로 Controller에서 관측되는 통신 흐름

Public Demo는 실제 SSH나 계정 입력을 사용하지 않습니다. 비식별 합성 Transport만 바꾸고, QueryRequest, TrackerService, production Parser와 MonitorEngine은 원 프로젝트 코드를 재사용합니다.

## 직접 실행

```sh
python -m pip install -r portfolio_demo/requirements.txt
python -m streamlit run portfolio_demo/app.py
python -m unittest discover -s portfolio_demo -p test_demo.py -v
```

자동 fixture/CI 결과와 실제 Aruba 장비·현장 PC 검증은 같은 증거 수준으로 표현하지 않습니다.
