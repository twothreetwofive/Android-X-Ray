"""static_analyzer 패키지 전체가 공유하는 커스텀 예외."""


class StaticAnalysisError(Exception):
    """정적 분석 파이프라인에서 발생하는 치명적 에러의 기본 클래스.

    apktool/jadx 실행 실패처럼 분석을 더 진행할 수 없는 경우에 발생시킨다.
    권한 파싱 실패처럼 일부만 실패한 경우는 예외 대신 analyze_static()의
    반환값 중 errors 리스트에 누적한다.
    """
