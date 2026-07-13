"""서드파티 SDK 시그니처 매칭.

jadx가 만든 소스 트리의 패키지 폴더 구조를 보고, 알려진 SDK 패키지 경로가
존재하는지 확인한다. 패키지명이 난독화된 경우는 못 잡음 — 알려진 SDK는
보통 자기 코드는 난독화 안 하는 경우가 많아서 실용적으로 쓸만함.
"""

from __future__ import annotations

from pathlib import Path

# 패키지 경로(슬래시 구분) -> SDK 이름. 필요한 만큼 계속 추가하면 됨.
KNOWN_SDK_PACKAGES = {
    "com/google/firebase": "Firebase",
    "com/google/android/gms": "Google Play Services",
    "com/facebook": "Facebook SDK",
    "com/appsflyer": "AppsFlyer",
    "com/squareup/okhttp3": "OkHttp",
    "com/squareup/retrofit2": "Retrofit",
    "com/unity3d": "Unity",
    "com/adjust/sdk": "Adjust",
    "com/kakao": "Kakao SDK",
    "com/naver": "Naver SDK",
}


def detect_sdks(extracted: dict) -> list[str]:
    jadx_dir = Path(extracted["jadx_dir"])
    detected = set()

    for pkg_path, sdk_name in KNOWN_SDK_PACKAGES.items():
        # jadx 버전에 따라 sources/ 하위에 소스가 들어가는 경우와 바로 루트인 경우가 있어 둘 다 확인
        if (jadx_dir / "sources" / pkg_path).exists() or (jadx_dir / pkg_path).exists():
            detected.add(sdk_name)

    return sorted(detected)
