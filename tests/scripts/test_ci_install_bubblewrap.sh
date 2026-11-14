#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
installer="$repo_root/scripts/ci/install-bubblewrap.sh"
scratch_dir=$(mktemp -d)
trap 'rm -rf -- "$scratch_dir"' EXIT

# Keep the archive and build offline while retaining the real tar command
fixture_dir="$scratch_dir/fixture"
commands_dir="$scratch_dir/commands"
mkdir -p "$fixture_dir/bubblewrap-0.13.1" "$commands_dir"
printf '%s\n' 'fixture source' > "$fixture_dir/bubblewrap-0.13.1/meson.build"
tar -cJf "$scratch_dir/source.tar.xz" -C "$fixture_dir" bubblewrap-0.13.1
real_tar=$(command -v tar)
real_sha256sum=$(command -v sha256sum)

cat > "$commands_dir/curl" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$TRACE_DIR/curl"
if [[ $TEST_CASE == download_failure ]]; then exit 28; fi
while [[ $# -gt 0 ]]; do
  if [[ $1 == --output ]]; then
    cp -- "$FIXTURE_ARCHIVE" "$2"
    exit
  fi
  shift
done
exit 1
COMMAND

cat > "$commands_dir/sha256sum" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
if [[ $TEST_CASE == wrong_hash ]]; then exec "$REAL_SHA256SUM" "$@"; fi
cat > "$TRACE_DIR/checksum"
[[ $TEST_CASE != checksum_failure ]]
COMMAND

cat > "$commands_dir/tar" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
touch "$TRACE_DIR/tar"
exec "$REAL_TAR" "$@"
COMMAND

cat > "$commands_dir/meson" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRACE_DIR/meson"
case $1 in
  setup)
    [[ -f $3/meson.build ]]
    mkdir -p "$2"
    ;;
  compile)
    [[ $2 == -C ]]
    if [[ $TEST_CASE == build_failure ]]; then exit 1; fi
    cat > "$3/bwrap" <<'BINARY'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == --version ]]
if [[ $TEST_CASE == version_failure ]]; then
  printf '%s\n' 'bubblewrap 0.13.1'
  exit 23
fi
if [[ $TEST_CASE == version_mismatch ]]; then
  printf '%s\n' 'bubblewrap 0.9.0'
else
  printf '%s\n' 'bubblewrap 0.13.1'
fi
BINARY
    chmod 755 "$3/bwrap"
    ;;
  *) exit 1 ;;
esac
COMMAND

cat > "$commands_dir/sudo" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$TRACE_DIR/sudo"
[[ $# == 6 && $1 == install && $2 == -m && $3 == 0755 && $4 == -- && $6 == /usr/bin/bwrap ]]
cp -- "$5" "$TRACE_DIR/installed"
COMMAND
chmod 755 "$commands_dir"/*

fail() {
  printf 'bubblewrap installer test failed: %s\n' "$1" >&2
  exit 1
}

run_case() {
  case_name=$1
  case_dir="$scratch_dir/$case_name"
  mkdir -p "$case_dir"
  if env PATH="$commands_dir:$PATH" TEST_CASE="$case_name" TRACE_DIR="$case_dir" \
    FIXTURE_ARCHIVE="$scratch_dir/source.tar.xz" REAL_TAR="$real_tar" \
    REAL_SHA256SUM="$real_sha256sum" bash "$installer" > "$case_dir/stdout" 2> "$case_dir/stderr"; then
    case_result=0
  else
    case_result=$?
  fi
}

# A successful build checks the published digest before installing the chosen binary
run_case success
[[ $case_result == 0 ]] || fail "success: $(< "$case_dir/stderr")"
grep -Fxq -- '--proto' "$case_dir/curl" || fail 'HTTPS protocol restriction'
grep -Fxq -- '--proto-redir' "$case_dir/curl" || fail 'HTTPS redirect restriction'
[[ $(grep -Fxc -- '=https' "$case_dir/curl") == 2 ]] || fail 'HTTPS-only values'
grep -Fxq -- 'https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz' "$case_dir/curl" || fail 'pinned source URL'
grep -Eq '^0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d  .*/bubblewrap\.tar\.xz$' "$case_dir/checksum" || fail 'pinned source digest'
[[ -e $case_dir/tar && -e $case_dir/installed ]] || fail 'source extraction and installation'
grep -q -- '--wrap-mode=nodownload' "$case_dir/meson" || fail 'offline Meson setup'
grep -q -- 'compile -C ' "$case_dir/meson" || fail 'Meson compilation'

# Each failed gate must stop before extraction, compilation, or installation as applicable
for case_name in download_failure checksum_failure wrong_hash build_failure version_mismatch version_failure; do
  run_case "$case_name"
  [[ $case_result != 0 ]] || fail "$case_name: expected failure"
  [[ ! -e $case_dir/installed && ! -e $case_dir/sudo ]] || fail "$case_name: unexpected installation"
  case $case_name in
    download_failure|checksum_failure|wrong_hash)
      [[ ! -e $case_dir/tar && ! -e $case_dir/meson ]] || fail "$case_name: unexpected extraction or build"
      ;;
    build_failure|version_mismatch|version_failure)
      [[ -e $case_dir/tar && -e $case_dir/meson ]] || fail "$case_name: build was not reached"
      ;;
  esac
  case $case_name in
    version_mismatch)
      grep -Fq -- 'unexpected bubblewrap version; expected 0.13.1' "$case_dir/stderr" || fail 'version mismatch diagnostic'
      ;;
    version_failure)
      grep -Fq -- 'failed to check bubblewrap version' "$case_dir/stderr" || fail 'failed version check diagnostic'
      ;;
  esac
done

printf '%s\n' 'bubblewrap installer tests passed'
