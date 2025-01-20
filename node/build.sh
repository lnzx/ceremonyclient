#!/bin/bash
set -euxo pipefail

# This script builds the node binary for the current platform and statically links it with VDF static lib.
# Assumes that the VDF library has been built by running the generate.sh script in the `../vdf` directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/node"
BINARIES_DIR="$ROOT_DIR/target/release"

pushd "$NODE_DIR" > /dev/null

export CGO_ENABLED=1

os_type="$(uname)"
case "$os_type" in
    "Darwin")
        # Check if the architecture is ARM
        if [[ "$(uname -m)" == "arm64" ]]; then
            # MacOS ld doesn't support -Bstatic and -Bdynamic, so it's important that there is only a static version of the library
            go build -ldflags "-linkmode 'external' -extldflags '-L$BINARIES_DIR -L/opt/homebrew/Cellar/mpfr/4.2.1/lib -I/opt/homebrew/Cellar/mpfr/4.2.1/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/flint/3.1.3-p1/lib -I/opt/homebrew/Cellar/flint/3.1.3-p1/include -lbls48581 -lstdc++ -lvdf -ldl -lm -lflint -lgmp -lmpfr'" "$@"
        else
            echo "Unsupported platform"
            exit 1
        fi
        ;;
    "Linux")
        export CGO_LDFLAGS="-L/usr/local/lib -lflint -lgmp -lmpfr -ldl -lm -L$BINARIES_DIR -lvdf -lbls48581 -static"
	go build -ldflags "-linkmode 'external'" "$@"
        ;;
    *)
        echo "Unsupported platform"
        exit 1
        ;;
esac
