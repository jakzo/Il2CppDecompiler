#!/bin/sh
source ./gradle.properties
set -eu

# Set these vars in env or gradle.properties before running this script:
# GHIDRA_INSTALL_DIR=~/Downloads/ghidra_11.0_PUBLIC
# GHIDRA_PROJECT_DIR=~/Downloads/boneworks
# GHIDRA_PROJECT_FILENAME=Boneworks.gpr
# GHIDRA_PROJECT_FILE=GameAssembly.dll
# FUNC_ADDRESS=18042fb81 # PhysicsRig.OnAfterFixedUpdate
# OPENAI_API_KEY=sk-...
# IL2CPPDUMPER_OUTPUT_DIR=~/Downloads/il2cppdumper/il2cpp_out

MAX_MEMORY="${MAX_MEMORY:-2G}"
MODE="${MODE:-fg}" # values: fg, debug, debug-suspend
DEBUG_ADDRESS="${DEBUG_ADDRESS:-127.0.0.1:13002}"

DEBUG_ADDRESS="$DEBUG_ADDRESS" "$GHIDRA_INSTALL_DIR/support/launch.sh" \
  "$MODE" \
  jdk \
  Ghidra-Headless \
  "$MAX_MEMORY" \
  "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2" \
  "ghidra.app.util.headless.AnalyzeHeadless" \
  "$GHIDRA_PROJECT_DIR" \
  "$GHIDRA_PROJECT_FILENAME" \
  -process "$GHIDRA_PROJECT_FILE" \
  -noanalysis \
  -readOnly \
  -scriptPath "$(dirname "$0")/ghidra_scripts" \
  -preScript "Il2CppDecompiler.java" \
  "$FUNC_ADDRESS" "$OPENAI_API_KEY" "$IL2CPPDUMPER_OUTPUT_DIR"
