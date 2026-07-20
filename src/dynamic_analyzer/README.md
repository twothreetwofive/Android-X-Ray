hooks.js에서 이 형식으로 send() 해보시고 이상하면 말씀해주세요 - 은아: 

    send({
        hook_type: "cipher",  // "string_builder" | "base64" | "cipher" | "custom_xor"
        timestamp: new Date().toISOString(),
        class_name: "javax.crypto.Cipher",
        method_name: "doFinal",
        raw_value: "...",  // 바이트면 Base64 인코딩해서 문자열로
        extra: { algorithm: "AES/CBC/PKCS5Padding", mode: "decrypt" },
        thread_id: Process.getCurrentThreadId()
    });

주의: frida가 한 번 더 감싸서 Python에서는 message["payload"]로 받게 됨 (C가 처리함)

+) 이거 JS임!! Python 아니에요 hook.js에서 사용하는 함수임

---

## B 작업 현황 

**완료**
- `hooks.js`: `string_builder`(`StringBuilder.append`) / `base64`(`Base64.decode`,`encodeToString`) / `cipher`(`Cipher.doFinal`) 3개 후킹 구현. C의 `schema.py` `HookEvent` 필드 그대로 맞춰서 `send()` 함.
- `hooks.js` 전송 전 사전 필터 추가: 최소 길이 미달(짧은 문자열/디코딩 결과), 과대 페이로드(cipher 결과 50KB 초과), 직전 호출과 동일한 값 연속 발생(루프성 중복) — 셋 다 명백한 노이즈라 판단되면 `send()` 자체를 스킵. C의 최종 분류/세션 통계와는 별개로, 소스 단에서 거를 수 있는 것만 미리 거른 것.

**미완료**
- `custom_xor`: 표준 API가 아니라 대상 앱이 자체적으로 짠 로직이라, 디컴파일된 실제 샘플(anubis.apk 등)을 보고 어느 클래스/메서드인지 특정해야 만들 수 있음. 지금 갖고 있는 악성코드 소스가 없어서 보류 — 디컴파일 결과 생기면 이어서 작업.

---

## B → C: 후킹 노이즈 필터링 조언 (4일차 몫)

hooks.js 3개(string_builder/base64/cipher) 다 걸어보면 실데이터에 악성 로직이랑 관계없는 호출이 훨씬 많이 섞여 들어올 것임. 그 중 명백하게 관계없는 부분은 이미 hooks.js에서 `send()` 전에 걸러서 안 보내게 해뒀고, 나머지는 실데이터를 봐야 판단 가능한 것들임.

**string_builder (`StringBuilder.append`)**
- 프레임워크/서드파티 SDK가 로그 찍고 문자열 조립할 때마다 계속 불려서 호출량이 제일 많음. 한 글자짜리 append도 수두룩함.
- ✅ hooks.js 구현: `raw_value` 길이 3자 이하 스킵, 직전 호출과 동일 값 연속 스킵.

**base64 (`Base64.decode`/`encodeToString`)**
- 이미지 리소스, SharedPreferences, 광고/크래시 리포팅 SDK(Firebase, Play Services 등)도 Base64를 일상적으로 씀 — 악성 행위랑 무관한 게 대부분일 가능성 높음.
- ✅ hooks.js 구현: decode/encode 결과 길이 5자 이하 스킵, 직전 호출과 동일 값 연속 스킵.
- ⬜ 구현 X: decode 결과가 출력 가능한 문자열(ASCII/UTF-8)인지 바이너리(이미지 등)인지 최종 분류해서 `plaintext_candidates`에 넣을지 판단하는 것 — 이건 hooks.js가 아니라 실데이터를 모아보는 message_parser.py 쪽에서 해야 함.

**cipher (`Cipher.doFinal`)**
- 요즘 앱은 HTTPS 통신 자체가 내부적으로 암복호화를 쓰기 때문에 정상 네트워크 스택에서도 호출이 많이 발생함.
- ✅ hooks.js 구현: 결과 페이로드 50KB 초과 시 스킵(이미지/파일 캐싱 추정), 직전 호출과 동일 값 연속 스킵.
- ⬜ 구현 X: `mode: "decrypt"` 결과가 UTF-8로 디코드했을 때 사람이 읽을 수 있는 문자열/JSON 형태인지 판단해서 우선순위 매기는 것(C2 응답, 탈취 데이터일 가능성) — 실데이터 기반 판단이라 message_parser.py 쪽 작업.

공통으로, 지금 hooks.js엔 "누가 호출했는지"(caller class) 정보가 없어서 프레임워크 내부 호출인지 앱 자체 로직인지 구분이 안된다고 하네요. 이 기능이 필요하면 말해주세요.. Frida에서 스택트레이스 찍어서 `extra`에 caller 정보 추가하는 것도 가능한데, 이러면 `schema.py`의 `extra` 내용 규칙이 바뀌는 거라 생각해보시고 정해주시면 좋을 것 같아요.

---

## D 작업 현황 (은서)

**완료**
- `adb_runner.py`: adb 래퍼. 디바이스 연결 확인, 앱 설치/실행 여부 확인(`is_installed`/`is_running`), 화면 조작(`tap`/`swipe`/`input_text`/`press_key`), 권한 부여(`grant_permission` — 좌표 탭 대신 `pm grant`로 결정적으로 처리).
- `scenarios.py`: 시나리오 3개 정의 — `launch_only`(베이스라인, 좌표 불필요, 지금 바로 실행 가능), `login_flow`/`permission_request`(실제 대상 앱 미정이라 좌표/권한값은 플레이스홀더, B의 `custom_xor`와 같은 이유로 보류). 사람이 읽는 설명은 `docs/동적분석/시나리오_정의서.md`.
- `scenario_runner.py`: A(`frida_controller.py`) + B(`hooks.bundle.js`) + C(`message_parser.py`)를 실제로 엮음. `spawn_and_attach → load_script → script.on("message", message_parser.on_message)`(A의 콘솔 출력용 리스너는 그대로 두고 별도 리스너 추가) `→ resume()` 순서로 실행한 뒤, adb로 시나리오 스텝을 재현하면서 스텝 사이마다 `is_running()`으로 크래시를 감지.
- 재현성 확인: `run_scenario_repeated()`로 같은 시나리오를 N회 반복 실행해 `total_events_filtered` 개수 편차 확인 — C가 4주차 과제에서 겪은 `waitForJava` 레이스 컨디션 같은 타이밍 문제가 있으면 여기서 드러남.
- 엣지 케이스: 디바이스 미연결/앱 미설치는 spawn 시도 전에 `_precheck()`에서 걸러냄. spawn 직후 크래시는 `wait_for_process()`로 최대 10초 폴링해서 감지.
- A/B가 4주차 보고서에서 남긴 "리포트가 실행마다 덮어써짐" 문제 해결: `dynamic_report_{시나리오명}_{실행시각}.json`으로 실행마다 별도 파일 저장.

**미완료 / 검증 안 됨**
- `login_flow`/`permission_request`의 실제 좌표·권한 문자열: anubis.apk 등 로그인 화면이 있는 실제 분석 대상이 이 저장소에 없어서 자리만 만들어둠.
- **실제 실행 검증 안 됨**: 이 코드를 작성한 환경엔 adb/frida-server/에뮬레이터가 없어서 `python -m py_compile`(문법 검사)만 통과했고, 실제 에뮬레이터에서 `scenario_runner.py`를 돌려본 적은 없음. 팀 에뮬레이터(`xray_api30`)가 있는 환경에서 A/B/C 코드와 실제로 맞물리는지 확인 필요 (5일차 통합 때 같이 확인).
- `controller._cleanup_current_session()`을 그대로 재사용함 (A의 private 메서드). 정리 로직이 A/D 양쪽에서 필요해진 거라, A 쪽에서 `cleanup()`처럼 public으로 노출해주면 더 깔끔할 것 같음 — 상의 필요.
