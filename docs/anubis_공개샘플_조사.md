# Anubis 등 실제 악성코드 공개 샘플 조사 (8주차 대비, 1주차 조사분)

8주차에 실제 뱅킹 악성코드(Anubis 계열)로 엔드투엔드 테스트를 하기 위해, 지금 시점에 샘플을 어디서 구할 수 있는지 미리 조사한 내용. **실행은 8주차, 조사는 지금.**

## 1. Anubis 악성코드 개요

- 2016년 Kaspersky가 처음 식별한 안드로이드 뱅킹 트로이목마. "Cron"이라는 러시아어권 그룹이 만든 것으로 추정됨.
- Accessibility Service를 악용한 오버레이 공격으로 300개 이상의 금융 앱 로그인 정보를 탈취.
- SMS 가로채기로 2단계 인증(OTP) 코드까지 탈취.
- 참고 자료: [MITRE ATT&CK - Anubis (S0422)](https://attack.mitre.org/software/S0422/), [n1ghtw0lf - Deep Analysis of Anubis Banking Malware](https://n1ght-w0lf.github.io/malware%20analysis/anubis-banking-malware/)

## 2. 공개 샘플 저장소 후보

| 저장소 | 특징 | 접근 방법 |
|---|---|---|
| **AndroZoo** | 안드로이드 앱 2,400만 개 이상 수집, 각 앱을 여러 백신 엔진으로 스캔해 악성 여부 태깅됨. 학계에서 가장 많이 쓰는 정식 데이터셋 | 이메일(androzoo@uni.lu)로 학술 목적 접근 계정 요청 필요. 팀/지도교수 명의로 신청 권장 |
| **VirusShare** | 8천만 개 이상의 악성코드 샘플 보관 | 이메일로 계정(access) 요청 필요 |
| **MalwareBazaar (abuse.ch)** | 안드로이드 태그(`android`)로 필터링해 샘플 검색 가능, 위협 인텔리전스 커뮤니티 대상 | 웹에서 바로 브라우징 가능: https://bazaar.abuse.ch/browse/tag/android/ |
| **GitHub 공개 샘플 모음** | 소규모지만 접근이 간편한 저장소들. 예: `MalwareSamples/Android-Malware-Samples`, `d-Raco/android-malware-source-code-samples` (Anubis 변종 포함) | 별도 승인 없이 클론 가능 (단, 실행/취급 주의) |

## 3. 팀 방향 제안

1. 이미 3~6월에 분석한 `anubis.apk`, `syssecapp.apk`가 있으므로, 1~7주차 개발/테스트는 이 두 샘플로 충분히 진행 가능.
2. 8주차에 "다른 Anubis 변종"으로 확장 테스트가 필요하면 위 표 중 **MalwareBazaar**가 가입 절차 없이 바로 접근 가능해 가장 빠름.
3. AndroZoo/VirusShare는 이메일 승인까지 시간이 걸릴 수 있으므로, 필요하다면 지금 미리 신청 메일을 보내두는 것을 권장 (승인까지 대기 시간 확보).
4. 실제 샘플을 다운로드/실행할 때는 발표자료 5번 리스크 항목대로 **반드시 네트워크 격리 환경 + 에뮬레이터 스냅샷 백업**을 먼저 구성한 뒤 진행.

## 참고 출처

- [Analysis of Anubis Trojan Attack on Android Banking Application - IIETA](https://www.iieta.org/journals/ijsse/paper/10.18280/ijsse.130104)
- [MITRE ATT&CK - Anubis (S0422)](https://attack.mitre.org/software/S0422/)
- [n1ghtw0lf - Deep Analysis of Anubis Banking Malware](https://n1ght-w0lf.github.io/malware%20analysis/anubis-banking-malware/)
- [Lookout Threat Intel - Anubis targets financial apps](https://www.lookout.com/threat-intelligence/article/anubis-targets-hundreds-of-financial-apps)
- [GitHub - d-Raco/android-malware-source-code-samples (Anubis 변종 포함)](https://github.com/d-Raco/android-malware-source-code-samples)
- [GitHub - MalwareSamples/Android-Malware-Samples](https://github.com/MalwareSamples/Android-Malware-Samples)
- [AndroZoo](https://androzoo.uni.lu/)
- [MalwareBazaar - android 태그](https://bazaar.abuse.ch/browse/tag/android/)
- [GitHub - antoniovh/Android-Malware-Dataset-Sources](https://github.com/antoniovh/Android-Malware-Dataset-Sources)
