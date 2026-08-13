"""analyze_static()의 출력 타입 정의. (A 작성, 3주차 과제2)

이 파일이 팀 공유 계약이다 — 아래 필드명/타입을 임의로 바꾸면 다른 모듈이 깨진다.
필드를 바꿔야 하면 팀 전체에 공유한 뒤 이 파일부터 고친다.
"""

from typing import Dict, List, TypedDict


class FileHash(TypedDict):
    md5: str
    sha1: str
    sha256: str


class Meta(TypedDict):
    # apk_name / analyzed_at은 6주차 통합 스키마의 required 필드라 B가 추가함.
    # apk_name은 apk_extractor에서, analyzed_at은 analyzer에서 채운다.
    apk_name: str
    analyzed_at: str  # 분석 시작 시각 (ISO 8601, UTC)
    package_name: str
    version_name: str
    version_code: int
    min_sdk: int
    target_sdk: int
    file_hash: FileHash
    file_size: int


class Component(TypedDict):
    type: str  # "activity" | "service" | "receiver" | "provider"
    name: str
    exported: bool
    intent_filters: List[str]  # 반응하는 action/category 이름


class ManifestInfo(TypedDict):
    permissions: List[str]
    dangerous_permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]
    exported_components: List[str]
    # 아래 components는 6주차 통합용으로 B가 추가한 필드(기존 필드는 그대로 둠).
    # activities/services/receivers/providers는 이름만 남아서 종류(type)와
    # intent-filter 내용이 사라지기 때문에, static_report.schema.json의
    # components 배열로 변환할 때는 이 필드를 쓴다.
    components: List[Component]


class CertInfo(TypedDict):
    issuer: str
    subject: str
    valid_from: str
    valid_to: str
    is_self_signed: bool


class CodeAnalysis(TypedDict):
    suspicious_api_calls: List[Dict[str, str]]  # {api, location, risk}
    obfuscation_detected: bool
    native_libraries: List[str]
    reflection_usage: bool
    dynamic_code_loading: bool
    # 8주차 추가: assets/res/raw에 숨은 "정체 불명의 큰 암호화 덩어리".
    # {path, size, apk_ratio, entropy, magic} 형태. 드로퍼가 2차 페이로드를
    # 코드가 아니라 자산으로 품고 있는 경우를 잡는다(code_scanner 주석 참고).
    packed_assets: List[Dict[str, object]]


class StringsInfo(TypedDict):
    urls: List[str]
    ip_addresses: List[str]
    suspicious_strings: List[str]


class BreakdownItem(TypedDict):
    # factor는 권한 이름("android.permission.CAMERA")일 수도 있고 집계 항목
    # ("exported_components×2 (3개)")일 수도 있다. 권한인 경우에만 PERMISSION_WEIGHTS /
    # ABUSE_EXAMPLES와 이름으로 다시 대조할 수 있다.
    factor: str
    weight: float


class RiskBreakdown(TypedDict):
    total: float  # 0.0 ~ 1.0, StaticAnalysisResult.risk_score와 항상 같은 값
    raw: float  # 정규화 전 합산 점수. items의 weight 합과 정확히 일치한다.
    breakdown: List[BreakdownItem]


class StaticAnalysisResult(TypedDict):
    meta: Meta
    manifest: ManifestInfo
    certificate: CertInfo
    code_analysis: CodeAnalysis
    strings: StringsInfo
    third_party_sdks: List[str]
    risk_score: float  # 0.0 ~ 1.0
    # 6주차 추가 필드(B). D의 calculate_risk_with_breakdown() 반환값을 그대로 담는다.
    # risk_score의 타입을 바꾸지 않으려고 형제 필드로 뺀 것이라 기존 8필드는 그대로다.
    # 계산 실패 시 risk_score와 같이 None이 된다.
    risk_breakdown: RiskBreakdown
    errors: List[str]  # 부분 실패 시 누적, 빈 리스트면 성공
