# scripts/wsl_env.sh — WSL에서 파이프라인을 돌리기 위한 환경 설정
#
# 사용:  source scripts/wsl_env.sh
#
# 하는 일: ~/tools 아래 설치한 분석 도구(JRE / apktool / jadx / adb)를 PATH에 넣는다.
# apktool·jadx는 static_analyzer/decompiler.py가 shutil.which()로 찾기 때문에
# 반드시 PATH에 있어야 하고, 없으면 정적 분석이 StaticAnalysisError로 통째로 실패한다.

export PATH="$HOME/tools/bin:$PATH"
export JAVA_HOME="$HOME/tools/jre"

echo "[wsl_env] apktool : $(command -v apktool || echo '없음')"
echo "[wsl_env] jadx    : $(command -v jadx || echo '없음')"
echo "[wsl_env] adb     : $(command -v adb || echo '없음')"
echo "[wsl_env] java    : $JAVA_HOME/bin/java"
