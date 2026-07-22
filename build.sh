#!/bin/bash
set -euo pipefail

gradle clean jar

# Copy latest built jar to repo root for easy download
jar_path="$(ls -t build/libs/*.jar | head -n 1)"
cp "$jar_path" ./
