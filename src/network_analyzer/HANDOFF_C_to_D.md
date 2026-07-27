# 3일차 인수인계 - C -> D

- sni_parser.py 완성, tls_sni 스키마 형식(sni/timestamp/dest_ip/dest_port) 검증 완료
- 샘플 출력: `sample_tls_sni_output.json` (본인 테스트 캡처 기준, 26개 SNI)

## 주의사항
- A의 실제 `output/capture.pcap`으로 돌려보면 TLS ClientHello 0개 - 파서 문제 아니라 캡처 자체 이슈로 확인됨 (TLS 세션 재사용 추정)
- 화이트리스트 대조 로직은 일단 이 샘플 데이터로 테스트 가능, 실제 앱 데이터는 A 재캡처 이후 다시 확인 필요