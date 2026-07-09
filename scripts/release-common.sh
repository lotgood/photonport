#!/bin/zsh

# Shared preflight for local release scripts. A release binary must be built
# from the exact clean commit named by its PhotonPort tag and already present
# on origin/main so GitHub's source archive is the corresponding source.

load_local_env() {
  if [[ -f .env ]]; then
    set -a
    source .env
    set +a
  fi
}

require_release_source() {
  local version="$1"
  local tag="photonport-v$version"
  local configured_version

  [[ "$version" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || {
    echo "version must be numeric MAJOR.MINOR.PATCH (got: $version)" >&2
    return 1
  }

  configured_version="$(awk -F'"' '/MARKETING_VERSION:/ { print $2; exit }' project.yml)"
  [[ "$configured_version" == "$version" ]] || {
    echo "project.yml MARKETING_VERSION is $configured_version, not $version" >&2
    return 1
  }

  [[ -z "$(git status --porcelain --untracked-files=normal)" ]] || {
    echo "release source is dirty; commit or remove every tracked/untracked change first" >&2
    git status --short >&2
    return 1
  }

  local head tag_commit remote_main
  head="$(git rev-parse HEAD)"
  tag_commit="$(git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)"
  [[ "$tag_commit" == "$head" ]] || {
    echo "tag $tag must exist and point at HEAD ($head)" >&2
    return 1
  }

  remote_main="$(git rev-parse -q --verify refs/remotes/origin/main 2>/dev/null || true)"
  [[ "$remote_main" == "$head" ]] || {
    echo "HEAD must already be pushed to origin/main before release" >&2
    return 1
  }

  export PHOTONPORT_RELEASE_TAG="$tag"
  export PHOTONPORT_RELEASE_COMMIT="$head"
}

require_acknowledgement() {
  local variable="$1"
  local guidance="$2"
  [[ "${(P)variable:-}" == "1" ]] || {
    echo "set $variable=1 only after $guidance" >&2
    return 1
  }
}
