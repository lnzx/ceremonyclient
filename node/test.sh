#!/bin/bash
set -euxo pipefail

# Run tests for the node package. Takes care of linking the native VDF. 
# Assumes that the VDF library has been built by running the generate.sh script in the `../vdf` directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/node"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link the native VDF and execute tests
pushd "$NODE_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -L/opt/homebrew/Cellar/mpfr/4.2.1/lib -I/opt/homebrew/Cellar/mpfr/4.2.1/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/flint/3.1.3-p1/lib -I/opt/homebrew/Cellar/flint/3.1.3-p1/include -lbls48581 -lstdc++ -lvdf -ldl -lm -lflint -lgmp -lmpfr" \
	CGO_ENABLED=1 \
  go test "$@"
