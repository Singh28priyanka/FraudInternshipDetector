#!/usr/bin/env bash
# Compile and launch the Fraud Internship Detector (macOS / Linux).
set -e
cd "$(dirname "$0")"
echo "Compiling…"
javac *.java
echo "Starting app…"
java Main
