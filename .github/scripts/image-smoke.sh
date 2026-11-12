#!/usr/bin/env bash
# Checks a runtime image built from the standalone template for what an
# operator relies on: it holds no Alpine package older than the Alpine
# repository's, and no package manager but apk (no npm, npx, corepack, pnpm or
# yarn).
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

pms="$(docker run --rm --entrypoint sh "$image" -c '
	for tool in npm npx corepack pnpm pnpx yarn yarnpkg; do
		command -v "$tool" || true
	done
	for dir in /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
		/usr/local/lib/node_modules/pnpm /usr/local/lib/node_modules/yarn /opt/yarn-v* \
		/home/node/.npm; do
		if [ -e "$dir" ]; then echo "$dir"; fi
	done')"
[ -z "$pms" ] || fail "the image carries a package manager: $pms"

echo "ok: $image"
