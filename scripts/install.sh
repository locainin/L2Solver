#!/bin/sh
# Keep Cargo and completion generation in the invoking user's process
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$script_dir/build_install.py" "$@"
