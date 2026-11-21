#!/usr/bin/env bash
set -euo pipefail

# These packages are built for the runner used by the release qualification
if [[ $(lsb_release -is) != Ubuntu || $(lsb_release -cs) != noble || $(dpkg --print-architecture) != amd64 ]]; then
  printf '%s\n' 'TShark CI installation requires Ubuntu 24.04 (noble) amd64' >&2
  exit 1
fi

version='4.6.9-1~ubuntu24.04.0~ppa1'
fingerprint='A2E402B85A4B70CD78D8A3D9D875551314ECA0F0'
scratch_dir=$(mktemp -d)
trap 'rm -rf -- "$scratch_dir"' EXIT
mkdir -m 700 "$scratch_dir/gnupg"

# Check the one primary key before granting its PPA any trust
curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --proto-redir '=https' --output "$scratch_dir/key.asc" \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$fingerprint"
if ! actual_fingerprint=$(gpg --batch --homedir "$scratch_dir/gnupg" --with-colons \
  --show-keys "$scratch_dir/key.asc" | awk -F: '
    $1 == "pub" { count++ }
    $1 == "fpr" && fingerprint == "" { fingerprint = $10 }
    END { if (count != 1 || fingerprint == "") exit 1; print fingerprint }
  '); then
  printf '%s\n' 'failed to verify the Wireshark PPA key' >&2
  exit 1
fi
if [[ $actual_fingerprint != "$fingerprint" ]]; then
  printf '%s\n' 'unexpected Wireshark PPA key fingerprint' >&2
  exit 1
fi
gpg --batch --homedir "$scratch_dir/gnupg" --dearmor \
  --output "$scratch_dir/key.gpg" "$scratch_dir/key.asc"

# Limit the verified key to this source instead of adding global APT trust
printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/wireshark-stable-ppa.gpg] https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu noble main' > "$scratch_dir/source.list"
sudo install -m 0644 -- "$scratch_dir/key.gpg" /usr/share/keyrings/wireshark-stable-ppa.gpg
sudo install -m 0644 -- "$scratch_dir/source.list" /etc/apt/sources.list.d/wireshark-stable-ppa.list

# Keep packet capture privileges disabled and install one matching release set
printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  "tshark=$version" "wireshark-common=$version" "libwireshark19=$version" \
  "libwiretap16=$version" "libwsutil17=$version" "libwireshark-data=$version"

# Refuse unexpected capture privileges or a mismatched executable
if ! dumpcap_mode=$(stat -c '%u:%g:%a' /usr/bin/dumpcap) || \
  ! dumpcap_capabilities=$(getcap /usr/bin/dumpcap); then
  printf '%s\n' 'failed to check dumpcap privileges' >&2
  exit 1
fi
if [[ $dumpcap_mode != '0:0:755' || -n $dumpcap_capabilities ]]; then
  printf '%s\n' 'dumpcap must not have elevated privileges' >&2
  exit 1
fi
if ! banner=$(tshark --version); then
  printf '%s\n' 'failed to check TShark version' >&2
  exit 1
fi
case ${banner%%$'\n'*} in
  'TShark (Wireshark) 4.6.9'|'TShark (Wireshark) 4.6.9.'|'TShark (Wireshark) 4.6.9 '*) ;;
  *) printf '%s\n' 'unexpected TShark version; expected 4.6.9' >&2; exit 1 ;;
esac
