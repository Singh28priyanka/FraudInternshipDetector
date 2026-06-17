#!/usr/bin/env bash
# Compile and launch the WEB version (opens at http://localhost:8090).
# Optional: pass a port, e.g.  ./web.sh 9000
set -e
cd "$(dirname "$0")"
echo "Compiling…"
javac *.java
echo "Starting web server…"
java WebServer "$@"
