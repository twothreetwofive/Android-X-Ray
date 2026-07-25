"""network_analyzer 패키지 전체가 공유하는 커스텀 예외."""


class NetworkAnalysisError(Exception):
    """네트워크 분석 파이프라인에서 발생하는 치명적 에러의 기본 클래스.

    tcpdump 실행 실패, pcap 파일을 찾을 수 없는 경우처럼 분석을 더 진행할 수
    없는 경우에 발생시킨다. 개별 패킷 파싱 실패처럼 일부만 실패한 경우는 예외
    대신 최종 반환값의 errors 리스트에 누적한다.
    """
# A가 새로 추가한 부분
class TcpdumpCaptureError(NetworkAnalysisError):
    """tcpdump 실행/종료/pull 과정에서 발생하는 에러 (Role A).

    NetworkAnalysisError를 상속하므로 오케스트레이션 레이어에서
    `except NetworkAnalysisError:` 한 번으로 캡처 실패까지 함께 잡힌다.
    """
