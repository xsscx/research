#!/usr/bin/env bash

set -euo pipefail

readonly LLVM_MAJOR=22
readonly LLVM_KEY_FINGERPRINT=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421

source /etc/os-release
codename="${VERSION_CODENAME:-}"
case "$codename" in
  jammy|noble|resolute)
    ;;
  *)
    printf '[FAIL] Unsupported Ubuntu codename for LLVM %s: %s\n' \
      "$LLVM_MAJOR" "${codename:-unknown}" >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
key_file="$tmp_dir/llvm-snapshot.gpg.key"
keyring_file="/usr/share/keyrings/apt.llvm.org.gpg"
source_file="/etc/apt/sources.list.d/apt.llvm.org.list"

curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  https://apt.llvm.org/llvm-snapshot.gpg.key \
  --output "$key_file"

actual_fingerprint="$(
  gpg --show-keys --with-colons "$key_file" |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
if [[ "$actual_fingerprint" != "$LLVM_KEY_FINGERPRINT" ]]; then
  printf '[FAIL] Unexpected apt.llvm.org signing-key fingerprint: %s\n' \
    "${actual_fingerprint:-missing}" >&2
  exit 1
fi

gpg --dearmor --yes --output "$tmp_dir/apt.llvm.org.gpg" "$key_file"
sudo install -o root -g root -m 0644 \
  "$tmp_dir/apt.llvm.org.gpg" "$keyring_file"
printf 'deb [signed-by=%s] https://apt.llvm.org/%s/ llvm-toolchain-%s-%s main\n' \
  "$keyring_file" "$codename" "$codename" "$LLVM_MAJOR" |
  sudo tee "$source_file" >/dev/null

sudo apt-get update -qq
