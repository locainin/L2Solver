#!/bin/sh
# Prepare the payload and completion files as an ordinary user
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$script_dir/build_install.py" "$@"
