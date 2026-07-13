# 모듈 간 JSON 스키마 (1주차 산출물)

정적/동적/네트워크 세 모듈이 각자 다른 형식으로 결과를 내면 6주차 파이프라인 통합 때 문제가 생기므로, 이 폴더에 세 모듈의 출력 스키마를 미리 정의해 둔다.

## 파일 구성

- `static_report.schema.json` — 정적 분석(JADX/Apktool + Manifest 파싱) 결과 스키마
- `dynamic_report.schema.json` — 동적 분석(Frida 후킹) 결과 스키마
- `network_report.schema.json` — 네트워크 분석(tcpdump + tshark/scapy) 결과 스키마

형식은 [JSON Schema Draft-07](https://json-schema.org/)을 사용했다. `required`는 반드시 있어야 하는 필드, `properties`는 각 필드의 타입과 설명이다.

## 각 파일에 뭐가 들어가는지

### static_report.json
- `meta`: 분석한 APK가 무엇인지 (패키지명, 해시, minSdk/targetSdk)
- `permissions`: Manifest의 `<uses-permission>` 목록 + 위험도(high/medium/low) + 악용 예시
- `components`: Activity/Service/Receiver/Provider와 각각의 intent-filter
- `risk_score`: 권한 가중치 합산 점수와 그 근거

### dynamic_report.json
- `meta`: 어떤 앱을 몇 초 동안 관찰했는지, 크래시 여부
- `hooked_calls`: `StringBuilder.append`, `Base64.decode/encode`, `Cipher.doFinal` 등 후킹 지점에서 잡힌 호출 기록
- `extracted_strings`: 정제(중복 제거, 최소 길이 필터, 패턴 매칭)를 거쳐 의미 있다고 판단된 문자열

### network_report.json
- `meta`: 캡처 시작 시각, 캡처 시간(Frida 실행 구간과 동기화됨), pcap 파일 경로
- `dns_queries`: 앱이 조회한 도메인 목록
- `tls_sni`: HTTPS 연결 시 평문으로 남는 SNI(목적지 도메인) 목록
- `suspicious`: 화이트리스트에 없어서 C&C 후보로 의심되는 도메인/IP

## 사용 방법

각 모듈 구현 시(2주차~5주차) 이 스키마의 필드명을 그대로 사용해서 결과 JSON을 생성한다. 필드를 추가/변경해야 하면 이 폴더의 스키마 파일을 먼저 고치고 팀원 전체에게 공유한 뒤 각자 코드에 반영한다. 임의로 필드명을 바꾸면 6주차 통합(`main.py` 오케스트레이터)에서 파싱 에러가 난다.

이 스키마는 초안이므로, 실제 구현하면서 필드가 부족하거나 불필요하면 팀 논의 후 수정 가능하다.
