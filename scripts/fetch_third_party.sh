#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party
cd third_party
clone() {
  if [ ! -d "$2" ]; then
    git -c advice.detachedHead=false clone --depth 1 ${3:+-b "$3"} "$1" "$2"
  fi
}
clone https://github.com/Mbed-TLS/mbedtls mbedtls-3.6.7 v3.6.7
clone https://github.com/Mbed-TLS/mbedtls mbedtls-2.28.10 v2.28.10
clone https://github.com/richgel999/miniz miniz
clone https://github.com/zserge/jsmn jsmn
clone https://github.com/mpaland/printf mprintf
echo "third_party ready"
