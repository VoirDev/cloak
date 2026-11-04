# shellcheck shell=bash disable=SC2034
# Shared definitions of the release scripts (docs/development.md#releases). Sourced, not run; every script
# runs from the repository root.

# The canonical version source. Gradle reads it; the npm packages get it when they are packed.
VERSION_FILE=VERSION

# The Maven artifacts: their group, the inventory file, where Gradle stages them, and where they are
# published. The registry is GitHub Packages of this repository.
MAVEN_GROUP=dev.voir.cloak
MAVEN_GROUP_PATH=${MAVEN_GROUP//.//}
PACKAGES_FILE=ci/release/packages
STAGED_REPOSITORY=build/release/repository

# The npm packages, packed on the release PR and published to GitHub Packages' npm registry, in
# dependency order: `name directory tarball-prefix`.
NPM_REGISTRY=https://npm.pkg.github.com
NPM_PACKAGES=(
  "@voirdev/cloak-crypto cloak-ts/packages/crypto voirdev-cloak-crypto"
  "@voirdev/cloak-client cloak-ts/packages/client voirdev-cloak-client"
)

# The workflow-run artifact that carries the built release from Verify to Publish Release, and its
# layout: `maven/` (the staged repository), `maven.sha256` (every file of it), `npm/` (the tarballs
# and their SHA256SUMS) and `VERSION`.
RELEASE_ARTIFACT=release-artifacts

fail() {
  echo "::error::$*" >&2
  exit 1
}

require_semver() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    fail "'$1' is not a MAJOR.MINOR.PATCH version."
}

# Prints the version in VERSION (or the file named), failing unless it is MAJOR.MINOR.PATCH.
read_version() {
  local version
  version="$(tr -d '[:space:]' <"${1:-$VERSION_FILE}")"
  require_semver "$version"
  printf '%s' "$version"
}

# Prints the artifactIds of the inventory, one per line, in its order.
read_packages() {
  grep -vE '^[[:space:]]*(#|$)' "$PACKAGES_FILE"
}
