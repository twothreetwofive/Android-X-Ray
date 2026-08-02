# 3일차 인수인계 - A -> B, C

- pcap 경로: `C:\Users\User\OneDrive - 이화여자대학교\문서\GitHub\Android-X-Ray\output\capture.pcap`
- 파일 크기: 613,353 bytes
- 전체 패킷 수: 390
- 검증 시각: 2026-07-25T16:04:06

## DNS (for B)
- 감지된 쿼리 수: 0
- 샘플: []

## TLS SNI (for C)
- 감지된 ClientHello 수: 0
- 샘플: []

## Capture Summary
```
====================================
| IO Statistics                    |
|                                  |
| Duration: 9.554 secs             |
| Interval: 9.554 secs             |
|                                  |
| Col  1: Frames and bytes         |
|----------------------------------|
|                |1                |
| Interval       | Frames |  Bytes |
|----------------------------------|
| 0.000 <> 9.554 |    390 | 607089 |
====================================
```

## Protocol Hierarchy
```
===================================================================
Protocol Hierarchy Statistics
Filter: 

frame                                    frames:390 bytes:607089
  sll                                    frames:390 bytes:607089
    ip                                   frames:389 bytes:606977
      tcp                                frames:389 bytes:606977
        http                             frames:2 bytes:480
        websocket                        frames:13 bytes:2361
          data                           frames:13 bytes:2361
        data                             frames:176 bytes:590640
    ipv6                                 frames:1 bytes:112
      icmpv6                             frames:1 bytes:112
===================================================================
```

## 주의사항
- [WARNING] DNS 쿼리가 없습니다. DoH/DoT 사용 또는 캡처 인터페이스 문제일 수 있습니다.
- [WARNING] TLS ClientHello가 없습니다. TLS 재사용(Session Resume), ECH 또는 평문 통신 가능성을 확인하세요.
- [WARNING] 패킷은 존재하지만 DNS/TLS가 모두 없습니다. protocol_hierarchy를 확인하여 실제 프로토콜을 분석하세요.