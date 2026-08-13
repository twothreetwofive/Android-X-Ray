#!/usr/bin/env bash
# scripts/snapshot.sh — 에뮬레이터 스냅샷 저장/복원/목록 (WSL에서 실행)
#
# 사용:
#   bash scripts/snapshot.sh list
#   bash scripts/snapshot.sh save before_run
#   bash scripts/snapshot.sh load before_run
#   bash scripts/snapshot.sh del  before_run
#
# 왜 래퍼가 필요한가:
#   `adb emu ...`는 adb 서버를 거치지 않고 **에뮬레이터 콘솔 포트(5554)에 직접**
#   붙는다. 그 포트는 Windows의 127.0.0.1에만 열려 있어서 WSL에서는 닿지 않는다
#   (WSL에서 실행하면 "could not connect to TCP port 5554: Connection refused").
#   그래서 이 명령만은 Windows adb.exe로 넘긴다. 인증 토큰(~/.emulator_console_auth_token)도
#   Windows 쪽에 있어서 그쪽에서 실행해야 통과된다.
#
# 왜 스냅샷을 쓰는가:
#   악성 샘플, 특히 드로퍼는 실행되면 2차 페이로드를 내려받아 **별도 패키지로**
#   설치한다. 그 경우 원래 앱을 uninstall해도 기기는 깨끗해지지 않는다.
#   실행 전 상태로 통째로 되돌리는 방법이 스냅샷이다.

set -u

ADB_WIN="${ADB_WIN:-/mnt/c/Android_AVD/platform-tools/adb.exe}"
if [ ! -x "$ADB_WIN" ]; then
    ADB_WIN=$(ls /mnt/c/Users/*/AppData/Local/Android/Sdk/platform-tools/adb.exe 2>/dev/null | head -1)
fi
if [ -z "${ADB_WIN:-}" ] || [ ! -x "$ADB_WIN" ]; then
    echo "[실패] Windows adb.exe를 찾을 수 없음. ADB_WIN=/mnt/c/.../adb.exe 로 지정할 것"
    exit 1
fi

ACTION="${1:-list}"
NAME="${2:-}"

case "$ACTION" in
    list)
        "$ADB_WIN" emu avd snapshot list 2>&1 | tr -d '\r'
        ;;
    save)
        [ -z "$NAME" ] && { echo "사용법: bash scripts/snapshot.sh save <이름>"; exit 1; }
        echo "스냅샷 저장 중... (40초쯤 걸림. 그동안 에뮬레이터가 잠깐 멈춤)"
        "$ADB_WIN" emu avd snapshot save "$NAME" 2>&1 | tr -d '\r'
        ;;
    load)
        [ -z "$NAME" ] && { echo "사용법: bash scripts/snapshot.sh load <이름>"; exit 1; }
        echo "스냅샷 복원 중... ($NAME 저장 시점 상태로 되돌아감)"
        "$ADB_WIN" emu avd snapshot load "$NAME" 2>&1 | tr -d '\r'
        echo
        echo "복원 후에는 frida-server가 꺼져 있을 수 있음. 아래를 다시 실행할 것:"
        echo "  bash scripts/prepare_emulator.sh"
        ;;
    del|delete)
        [ -z "$NAME" ] && { echo "사용법: bash scripts/snapshot.sh del <이름>"; exit 1; }
        "$ADB_WIN" emu avd snapshot delete "$NAME" 2>&1 | tr -d '\r'
        ;;
    *)
        echo "사용법: bash scripts/snapshot.sh {list|save|load|del} [이름]"
        exit 1
        ;;
esac
