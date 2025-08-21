#!/bin/bash
set -e

# Extract coverage from cobertura.xml
COVERAGE=$(grep -oP 'line-rate="\K[^"]*' cobertura.xml | head -1 | awk '{printf "%.1f", $1*100}')

echo "Coverage: ${COVERAGE}%"

# Check if coverage is above 90% (using awk for comparison)
if awk "BEGIN {exit !($COVERAGE >= 90)}"; then
  echo "✅ Coverage above 90%: ${COVERAGE}%"
  exit 0
else
  echo "❌ Coverage below 90%: ${COVERAGE}%"  
  exit 1
fi
