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


class StringsInfo(TypedDict):
    urls: List[str]
    ip_addresses: List[str]
    suspicious_strings: List[str]


class StaticAnalysisResult(TypedDict):
    meta: Meta
    manifest: ManifestInfo
    certificate: CertInfo
    code_analysis: CodeAnalysis
    strings: StringsInfo
    third_party_sdks: List[str]
    risk_score: float  # 0.0 ~ 1.0
    errors: List[str]  # 부분 실패 시 누적, 빈 리스트면 성공
