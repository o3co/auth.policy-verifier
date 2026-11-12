#!/usr/bin/env bash
# Checks a runtime image built from the standalone template for what an
# operator relies on: it holds no Alpine package older than the Alpine
# repository's.
#
# Usage: image-smoke.sh <image>
set -euo pipefail

image="${1:?usage: image-smoke.sh <image>}"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# apk prints a header line, then one line per installed package that the
# repository holds a newer version of.
stale="$(docker run --rm --user root --entrypoint sh "$image" -c 'apk update -q >/dev/null && apk version -l "<"' | tail -n +2)"
[ -z "$stale" ] || fail "Alpine packages older than the repository's: $stale"

echo "ok: $image"
