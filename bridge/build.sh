#!/bin/bash
# Build script for mihomo Go parser bridge
# Supports both dynamic (.so) and static (.a) linking modes
#
# Usage:
#   ./build.sh          - Build .so (c-shared, default, for Alpine/musl)
#   ./build.sh static   - Build .a (c-archive, for glibc systems)
#   ./build.sh so       - Build .so (c-shared, explicit)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_MODE="${1:-so}"

case "$BUILD_MODE" in
    so|shared|dynamic|c-shared)
        echo "Building mihomo Go bridge as shared library (.so)..."
        go build -buildmode=c-shared -o libmihomo.so .
        echo "Done: libmihomo.so"
        ;;
    static|a|c-archive)
        echo "Building mihomo Go bridge as static library (.a)..."
        go build -buildmode=c-archive -o libmihomo.a .
        echo "Done: libmihomo.a"
        ;;
    *)
        echo "Usage: $0 {so|static}"
        echo "  so      - Build .so (c-shared, default)"
        echo "  static  - Build .a (c-archive)"
        exit 1
        ;;
esac
