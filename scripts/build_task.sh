#!/usr/bin/env bash

# Copyright (c) 2025 HomomorphicEncryption.org
# All rights reserved.
#
# This software is licensed under the terms of the Apache v2 License.
# See the LICENSE.md file for details.

# ------------------------------------------------------------
# Usage: ./scripts/build_task.sh
# Compiles the files in the source directory.
# ------------------------------------------------------------
set -euo pipefail
ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
TASK_DIR="submission"
BUILD="$TASK_DIR/build"
export CC=$(command -v clang || echo cc)
export CXX=$(command -v clang++ || echo c++)

# By default, we assume the OpenFHE library is installed at the the local 
# directory /third_party/openfhe (the default location in get_openfhe.sh).
# If you want to use a different location, set the CMAKE_PREFIX_PATH variable
# accordingly.
cmake -S "$TASK_DIR" -B "$BUILD" \
      -DCMAKE_PREFIX_PATH="$ROOT/third_party/openfhe" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_CXX_COMPILER="$CXX"
cd "$TASK_DIR/build"
make -j

# now make it compatible with harness
cd ../..
mkdir -p "$TASK_DIR/target/release"
cp "$BUILD"/client_* "$BUILD"/server_* "$TASK_DIR/target/release/"
