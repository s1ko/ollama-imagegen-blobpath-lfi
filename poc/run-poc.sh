#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${1:?usage: run-poc.sh /path/to/ollama-checkout}" && pwd)"

manifest_dir="$repo/x/imagegen/manifest"
transfer_dir=""
for candidate in x/imagegen/transfer x/transfer transfer; do
  if [ -f "$repo/$candidate/download.go" ]; then
    transfer_dir="$repo/$candidate"
    break
  fi
done
[ -n "$transfer_dir" ] || { echo "no transfer package found under $repo" >&2; exit 1; }

copied=()
cleanup() {
  if [ "${#copied[@]}" -gt 0 ]; then
    rm -f "${copied[@]}"
  fi
}
trap cleanup EXIT

packages=()
if [ -d "$manifest_dir" ]; then
  cp "$here/poc_blobpath_test.go" "$manifest_dir/poc_test.go"
  copied+=("$manifest_dir/poc_test.go")
  packages+=("./x/imagegen/manifest/")
else
  echo "x/imagegen/manifest not present in this checkout: BlobPath tests skipped"
fi
cp "$here/poc_download_test.go" "$transfer_dir/poc_test.go"
copied+=("$transfer_dir/poc_test.go")
packages+=("./${transfer_dir#"$repo"/}/")

cd "$repo"
go test "${packages[@]}" -run 'TestPoC_' -v
