#!/usr/bin/env bash
# Generate the javax.servlet variant of the SDK from the jakarta sources.
#
#   ./scripts/gen-javax.sh [outdir]     # default: target/javax-src
#
# The jakarta and javax servlet APIs differ only in package name for everything
# this SDK touches, so the variant is GENERATED rather than maintained as a
# second copy. Two copies of the same engine drift, and the copy nobody runs is
# the one that drifts — this repo has already learned that from its SDKs.
#
# Spring Boot 2 and Tomcat 9 are javax; Spring Boot 3, Quarkus 3 and Tomcat 10+
# are jakarta.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-target/javax-src}"
SRC="src/main/java/io/github/dwarkaprasad/optictrace"
TEST_SRC="src/test/java/io/github/dwarkaprasad/optictrace"
DEST="$OUT/io/github/dwarkaprasad/optictrace"

rm -rf "$OUT"
mkdir -p "$DEST"

# The test suite is rewritten too, so the variant can be RUN and not merely
# compiled. A generated copy nobody executes is the copy that breaks.
for f in "$SRC"/*.java "$TEST_SRC"/*.java; do
  # Only the import lines and any qualified references change. Nothing else in
  # this SDK is servlet-version specific — if that stops being true, this script
  # should start failing rather than silently producing something that compiles
  # and misbehaves, which is what the grep below is for.
  sed 's/\bjakarta\.servlet\b/javax.servlet/g' "$f" > "$DEST/$(basename "$f")"
done

# A jakarta reference surviving the rewrite means a new API surface appeared
# that this script does not know about.
if grep -rn "jakarta\." "$DEST" >/dev/null 2>&1; then
  echo "✗ jakarta references survived the rewrite:" >&2
  grep -rn "jakarta\." "$DEST" >&2
  exit 1
fi

count=$(find "$DEST" -name '*.java' | wc -l | tr -d ' ')
echo "✓ generated $count javax source file(s) in $OUT"
echo "  compile with javax.servlet:javax.servlet-api:4.0.1 on the classpath"
