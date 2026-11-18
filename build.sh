#!/usr/bin/env bash
# Build dnslog-everywhere.jar from source.
#
#   BURP_JAR=/path/to/burpsuite_pro.jar ./build.sh
#
# BURP_JAR may point at a full Burp install or a standalone montoya-api.jar
# (https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

API_JAR="${BURP_JAR:-}"
if [[ -z "$API_JAR" ]]; then
  for candidate in "$ROOT"/lib/*.jar; do
    [[ -f "$candidate" ]] && API_JAR="$candidate" && break
  done
fi
if [[ -z "$API_JAR" || ! -f "$API_JAR" ]]; then
  cat >&2 <<'EOF'
[ERROR] Burp / Montoya API jar not found.

Set BURP_JAR=/path/to/burpsuite_pro.jar  (or drop a jar into ./lib/)
Standalone API jar also works:
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/
EOF
  exit 1
fi

JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/javac}"; JAVAC="${JAVAC:-javac}"
JAR="${JAVA_HOME:+$JAVA_HOME/bin/jar}";     JAR="${JAR:-jar}"
command -v "$JAVAC" >/dev/null || { echo "javac not found (install JDK 17+)" >&2; exit 1; }

echo "API jar : $API_JAR"
rm -rf build stage
mkdir -p build stage/dnslogeverywhere dist

"$JAVAC" -encoding UTF-8 -nowarn -cp "$API_JAR" -d build src/main/java/dnslogeverywhere/*.java

# Only ship our own classes (see build.ps1 for why).
cp build/dnslogeverywhere/*.class stage/dnslogeverywhere/
rm -f dist/dnslog-everywhere.jar
"$JAR" cf dist/dnslog-everywhere.jar -C stage .

ls -l dist/dnslog-everywhere.jar
