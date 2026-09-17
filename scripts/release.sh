#!/usr/bin/env bash
#
# Release build (requirement 16.1).
#
# Produces one statically linked binary per platform under dist/, plus a
# SHA256SUMS file covering them. Run from the repository root:
#
#   ./scripts/release.sh                       # version derived from git
#   VERSION=v0.3.0 ./scripts/release.sh        # version pinned by hand
#   PLATFORMS="linux/arm64" ./scripts/release.sh   # one target only
#   OUT=/tmp/rel ./scripts/release.sh          # somewhere other than dist/
#
# Three properties matter here, and each one is bought by a specific flag.
#
#   CGO_ENABLED=0  makes the binary self-contained. With cgo on, the Go resolver
#                  can bind to the platform's libc for DNS, which is exactly the
#                  runtime dependency requirement 16.1 rules out — and the reason
#                  the tool can be copied onto a jump host that has nothing on it.
#
#   -trimpath      strips the build machine's directory layout from the binary,
#   -buildvcs=false and drops the VCS stamp the toolchain would otherwise embed.
#                  Together with a fixed Go version they make the output a
#                  function of the commit alone: the same commit rebuilt on
#                  another machine yields the same bytes, so a checksum published
#                  next to a release means something.
#
#   -ldflags -X    stamps the version into the one variable the binary reports,
#                  internal/cli.Version. It defaults to "dev", so an unstamped
#                  build is visibly unstamped rather than silently claiming a
#                  release number.
#
# Failures do not stop the run. Every target is attempted so one broken platform
# reports as one line rather than hiding the state of the rest; the script exits
# non-zero if any target failed.
#
set -uo pipefail

PKG=./cmd/aws-netpath
LDPATH=github.com/jajera/aws-netpath/internal/cli.Version
OUT=${OUT:-dist}

# The matrix covers what an operator plausibly runs the tool from: a Linux jump
# host or CI runner on either architecture, a developer laptop on either Apple
# platform, and Windows on amd64.
PLATFORMS=${PLATFORMS:-"
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
"}

# ---------------------------------------------------------------------------
# Provenance.
#
# VERSION is the tag when the commit carries one and "dev" when it does not, so
# a build off a branch never presents itself as a release. COMMIT is recorded
# separately and marked dirty when the worktree has uncommitted changes, because
# a binary built from an unclean tree cannot be reproduced from the commit.
# ---------------------------------------------------------------------------
VERSION=${VERSION:-$(git describe --tags --match 'v*' 2>/dev/null)}
VERSION=${VERSION:-dev}

COMMIT=$(git rev-parse --short HEAD 2>/dev/null) || COMMIT=unknown
# Untracked files count as dirty as much as modified ones do: a stray .go file in
# the tree changes what gets compiled.
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  COMMIT="${COMMIT}-dirty"
fi

# Joined with "+" as semver build metadata rather than separated by a space: the
# -ldflags value is split on whitespace by the toolchain, so a stamp with a space
# in it does not survive the trip to the linker.
STAMP="${VERSION}+${COMMIT}"
SLUG=${VERSION//\//-}

echo "aws-netpath release build"
echo "  version   ${VERSION}"
echo "  commit    ${COMMIT}"
echo "  toolchain $(go version)"
echo "  output    ${OUT}/"
echo

mkdir -p "$OUT" || exit 2

fail=0
artefacts=()

for platform in $PLATFORMS; do
  goos=${platform%%/*}
  goarch=${platform##*/}

  name="aws-netpath_${SLUG}_${goos}_${goarch}"
  [[ "$goos" == "windows" ]] && name="${name}.exe"

  printf '  %-24s ' "${goos}/${goarch}"

  if ! CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags "-s -w -X ${LDPATH}=${STAMP}" \
      -o "${OUT}/${name}" \
      "$PKG"; then
    echo "FAILED"
    fail=1
    continue
  fi

  artefacts+=("$name")
  echo "$name"
done

echo

# ---------------------------------------------------------------------------
# Checks on what was produced.
#
# The static claim is checked rather than assumed. On ELF targets `file` states
# it outright, so a build that somehow picked up a dynamic link is caught here
# instead of on the jump host. Mach-O and PE binaries always link their platform
# loader stub, so there is nothing equivalent to assert for them; CGO_ENABLED=0
# is what carries the property there.
# ---------------------------------------------------------------------------
if ((${#artefacts[@]} > 0)) && command -v file >/dev/null 2>&1; then
  for name in "${artefacts[@]}"; do
    [[ "$name" == *_linux_* ]] || continue
    described=$(file -b "${OUT}/${name}")
    if [[ "$described" == *"dynamically linked"* ]]; then
      echo "  $name is dynamically linked: $described"
      fail=1
    fi
  done
fi

# The host binary is the only one that can be run, so it is the only one whose
# stamp can be confirmed end to end: what the binary prints has to be what the
# ldflags said.
host="aws-netpath_${SLUG}_$(go env GOHOSTOS)_$(go env GOHOSTARCH)"
if [[ -x "${OUT}/${host}" ]]; then
  reported=$("${OUT}/${host}" version)
  if [[ "$reported" != "$STAMP" ]]; then
    echo "  ${host} reports version ${reported}, want ${STAMP}"
    fail=1
  fi
fi

# ---------------------------------------------------------------------------
# Checksums.
#
# Written from inside the output directory so the file names in SHA256SUMS are
# bare, which is what `sha256sum -c SHA256SUMS` expects a consumer to have next
# to it after downloading a release.
# ---------------------------------------------------------------------------
if ((${#artefacts[@]} > 0)); then
  if command -v sha256sum >/dev/null 2>&1; then
    sum() { sha256sum "$@"; }
  elif command -v shasum >/dev/null 2>&1; then
    sum() { shasum -a 256 "$@"; }
  else
    echo "no sha256sum or shasum available; skipping checksums"
    sum() { return 1; }
  fi

  if (cd "$OUT" && sum "${artefacts[@]}" >SHA256SUMS); then
    echo "checksums:"
    sed 's/^/  /' "${OUT}/SHA256SUMS"
  fi
fi

echo
if ((fail != 0)); then
  echo "release build FAILED"
  exit 1
fi
echo "release build ok: ${#artefacts[@]} artefacts in ${OUT}/"
