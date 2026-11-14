#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
installer="$repo_root/scripts/ci/install-tshark.sh"
scratch_dir=$(mktemp -d)
trap 'rm -rf -- "$scratch_dir"' EXIT
commands_dir="$scratch_dir/commands"
mkdir -p "$commands_dir"

# Replace host-changing commands while recording their inputs and order
cat > "$commands_dir/lsb_release" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
case $1 in
  -is) if [[ $TEST_CASE == wrong_vendor ]]; then printf '%s\n' Debian; else printf '%s\n' Ubuntu; fi ;;
  -cs) if [[ $TEST_CASE == wrong_release ]]; then printf '%s\n' jammy; else printf '%s\n' noble; fi ;;
  *) exit 1 ;;
esac
COMMAND

cat > "$commands_dir/dpkg" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == --print-architecture ]]
if [[ $TEST_CASE == wrong_arch ]]; then printf '%s\n' arm64; else printf '%s\n' amd64; fi
COMMAND

cat > "$commands_dir/curl" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$TRACE_DIR/curl"
[[ $TEST_CASE != download_failure ]] || exit 28
while [[ $# -gt 0 ]]; do
  if [[ $1 == --output ]]; then
    printf '%s\n' 'fixture key' > "$2"
    exit
  fi
  shift
done
exit 1
COMMAND

cat > "$commands_dir/gpg" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *' --show-keys '*)
    printf '%s\n' 'pub:-:4096:1:1234:::::::::'
    if [[ $TEST_CASE == wrong_key ]]; then
      printf '%s\n' 'fpr:::::::::0000000000000000000000000000000000000000:'
    else
      printf '%s\n' 'fpr:::::::::A2E402B85A4B70CD78D8A3D9D875551314ECA0F0:'
    fi
    if [[ $TEST_CASE == extra_key ]]; then printf '%s\n' 'pub:-:4096:1:5678:::::::::'; fi
    if [[ $TEST_CASE == key_command_failure ]]; then exit 23; fi
    ;;
  *' --dearmor '*)
    touch "$TRACE_DIR/dearmor"
    while [[ $# -gt 0 ]]; do
      if [[ $1 == --output ]]; then
        printf '%s\n' 'fixture keyring' > "$2"
        exit
      fi
      shift
    done
    exit 1
    ;;
  *) exit 1 ;;
esac
COMMAND

cat > "$commands_dir/sudo" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRACE_DIR/sudo"
case $1 in
  install)
    [[ $# == 6 && $2 == -m && $3 == 0644 && $4 == -- ]]
    case $6 in
      /usr/share/keyrings/wireshark-stable-ppa.gpg) cp -- "$5" "$TRACE_DIR/keyring" ;;
      /etc/apt/sources.list.d/wireshark-stable-ppa.list) cp -- "$5" "$TRACE_DIR/source" ;;
      *) exit 1 ;;
    esac
    ;;
  debconf-set-selections) cat > "$TRACE_DIR/debconf" ;;
  apt-get) [[ $2 == update && $TEST_CASE != update_failure ]] ;;
  env)
    [[ $2 == DEBIAN_FRONTEND=noninteractive && $3 == apt-get && $4 == install ]]
    [[ $TEST_CASE != install_failure ]]
    ;;
  *) exit 1 ;;
esac
COMMAND

cat > "$commands_dir/stat" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -c && $2 == '%u:%g:%a' && $3 == /usr/bin/dumpcap ]]
if [[ $TEST_CASE == stat_failure ]]; then exit 1; fi
if [[ $TEST_CASE == unsafe_mode ]]; then printf '%s\n' '0:0:4755'; else printf '%s\n' '0:0:755'; fi
COMMAND

cat > "$commands_dir/getcap" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == /usr/bin/dumpcap ]]
if [[ $TEST_CASE == getcap_failure ]]; then exit 1; fi
if [[ $TEST_CASE == unsafe_capabilities ]]; then printf '%s\n' '/usr/bin/dumpcap cap_net_raw=ep'; fi
COMMAND

cat > "$commands_dir/tshark" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == --version ]]
if [[ $TEST_CASE == wrong_version ]]; then
  printf '%s\n' 'TShark (Wireshark) 4.6.8.'
elif [[ $TEST_CASE == wrong_version_prefix ]]; then
  printf '%s\n' 'TShark (Wireshark) 4.6.90.'
else
  printf '%s\n' 'TShark (Wireshark) 4.6.9.'
fi
if [[ $TEST_CASE == version_failure ]]; then exit 23; fi
COMMAND
chmod 755 "$commands_dir"/*

fail() {
  printf 'tshark installer test failed: %s\n' "$1" >&2
  exit 1
}

run_case() {
  case_name=$1
  case_dir="$scratch_dir/$case_name"
  mkdir -p "$case_dir"
  if env PATH="$commands_dir:$PATH" TEST_CASE="$case_name" TRACE_DIR="$case_dir" \
    bash "$installer" > "$case_dir/stdout" 2> "$case_dir/stderr"; then
    case_result=0
  else
    case_result=$?
  fi
}

# A successful install trusts only the verified PPA key and pins every release package
run_case success
[[ $case_result == 0 ]] || fail "success: $(< "$case_dir/stderr")"
grep -Fxq -- '--proto' "$case_dir/curl" || fail 'HTTPS protocol restriction'
grep -Fxq -- '--proto-redir' "$case_dir/curl" || fail 'HTTPS redirect restriction'
[[ $(grep -Fxc -- '=https' "$case_dir/curl") == 2 ]] || fail 'HTTPS-only values'
grep -Fxq -- 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xA2E402B85A4B70CD78D8A3D9D875551314ECA0F0' "$case_dir/curl" || fail 'verified key URL'
grep -Fxq -- 'deb [arch=amd64 signed-by=/usr/share/keyrings/wireshark-stable-ppa.gpg] https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu noble main' "$case_dir/source" || fail 'scoped PPA source'
grep -Fxq -- 'wireshark-common wireshark-common/install-setuid boolean false' "$case_dir/debconf" || fail 'unprivileged dumpcap selection'
for package in tshark wireshark-common libwireshark19 libwiretap16 libwsutil17 libwireshark-data; do
  grep -Fq -- "$package=4.6.9-1~ubuntu24.04.0~ppa1" "$case_dir/sudo" || fail "pinned package: $package"
done

# A rejected key must never reach root-owned repository configuration
for case_name in wrong_vendor wrong_release wrong_arch download_failure wrong_key extra_key key_command_failure; do
  run_case "$case_name"
  [[ $case_result != 0 && ! -e $case_dir/sudo ]] || fail "$case_name: unexpected root command"
done
for case_name in wrong_vendor wrong_release wrong_arch; do
  grep -Fq -- 'TShark CI installation requires Ubuntu 24.04 (noble) amd64' "$scratch_dir/$case_name/stderr" || fail "$case_name: missing platform diagnostic"
done

# Failed package or runtime checks must keep the installer in a failed state
for case_name in update_failure install_failure unsafe_mode unsafe_capabilities stat_failure getcap_failure wrong_version wrong_version_prefix version_failure; do
  run_case "$case_name"
  [[ $case_result != 0 ]] || fail "$case_name: expected failure"
done
if grep -Fq -- 'apt-get install ' "$scratch_dir/update_failure/sudo"; then fail 'install attempted after failed update'; fi
grep -Fq -- 'failed to check TShark version' "$scratch_dir/version_failure/stderr" || fail 'failed version command diagnostic'

printf '%s\n' 'tshark installer tests passed'
