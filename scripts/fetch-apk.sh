#!/usr/bin/env bash
# Downloads the Android client APK from the GitHub release of
# lange232/deeps-kaskad-client into files/app/app.apk, verifying it against
# the SHA256SUMS.txt published with the same release.
#
# The panel distributes whatever file is in files/app/app.apk, so this is the
# only step needed before `ansible-playbook --tags panel`. Nothing is written
# when the checksum does not match: a bad download never replaces a good APK.
#
# Usage:
#   scripts/fetch-apk.sh                  # latest release
#   scripts/fetch-apk.sh --tag v5.8.2     # a pinned release
#   scripts/fetch-apk.sh --out /tmp/a.apk # somewhere else
#
# Set GITHUB_TOKEN to raise the anonymous API rate limit (60 requests/hour
# per address). Release assets themselves need no auth and are fetched from
# objects.githubusercontent.com after a redirect, hence curl -L.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="${KASKAD_APK_REPO:-lange232/deeps-kaskad-client}"
TAG=""
OUT="files/app/app.apk"

while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="${2:?--tag needs a value}"; shift 2 ;;
        --out) OUT="${2:?--out needs a value}"; shift 2 ;;
        --repo) REPO="${2:?--repo needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

api() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$1"
    else
        curl -fsSL "$1"
    fi
}

if [ -n "$TAG" ]; then
    api "https://api.github.com/repos/$REPO/releases/tags/$TAG" > "$tmp/release.json"
else
    api "https://api.github.com/repos/$REPO/releases/latest" > "$tmp/release.json"
fi

# Asset names follow deepskaskad-standalone-v<versionName>-arm64.apk.
read -r tag apk_url sums_url < <(python3 - "$tmp/release.json" <<'PY'
import json, sys

data = json.load(open(sys.argv[1]))
assets = {a["name"]: a["browser_download_url"] for a in data["assets"]}
arm64 = [name for name in assets if name.endswith("-arm64.apk")]
if len(arm64) != 1:
    sys.exit(f"expected one -arm64.apk asset, found {arm64 or 'none'}")
if "SHA256SUMS.txt" not in assets:
    sys.exit("release has no SHA256SUMS.txt, refusing to guess a checksum")
print(data["tag_name"], assets[arm64[0]], assets["SHA256SUMS.txt"])
PY
)

asset="${apk_url##*/}"
echo "release $tag, asset $asset"

curl -fsSL -o "$tmp/SHA256SUMS.txt" "$sums_url"
curl -fsSL -o "$tmp/app.apk" "$apk_url"

expected="$(awk -v name="$asset" '
    { path = $2; sub(/^\.\//, "", path) }
    path == name { print $1; exit }
' "$tmp/SHA256SUMS.txt")"
if [ -z "$expected" ]; then
    echo "SHA256SUMS.txt has no entry for $asset" >&2
    cat "$tmp/SHA256SUMS.txt" >&2
    exit 1
fi

actual="$(sha256sum "$tmp/app.apk" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $asset: expected $expected, got $actual" >&2
    echo "the file was not installed" >&2
    exit 1
fi

if [ -f "$OUT" ] && [ "$(sha256sum "$OUT" | cut -d' ' -f1)" = "$expected" ]; then
    echo "$OUT is already $tag ($expected)"
    exit 0
fi

install -m 0644 "$tmp/app.apk" "$OUT"
echo "installed $OUT from $tag"
echo "sha256 $actual"
