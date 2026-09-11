#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'release-artifact: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "falta el comando requerido: $1"
}

require_value() {
  local name="$1"
  local value="${!name:-}"
  test -n "$value" || die "falta la variable requerida: $name"
}

require_digest() {
  local digest="$1"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "digest OCI no valido: $digest"
}

is_not_found_error() {
  local error_file="$1"
  LC_ALL=C grep -Eiq '(^|[^[:alnum:]])(404|not[[:space:]-]+found|manifest[[:space:]]+unknown|name[[:space:]]+unknown)([^[:alnum:]]|$)' "$error_file"
}

temp_file() {
  local temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  test -d "$temp_root" || die "el directorio temporal no existe: $temp_root"
  mktemp "$temp_root/release-artifact.XXXXXX"
}

manifest_digest() {
  local manifest_file="$1"
  jq -er '.digest | strings | select(test("^sha256:[0-9a-f]{64}$"))' "$manifest_file"
}

verify_attestation() { # <image> <digest> <repo> <workflow> <commit> <ref>
  local image="$1" digest="$2" repository="$3" workflow="$4" commit="$5" ref="$6"
  require_command gh
  require_digest "$digest"
  [[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "repositorio de attestation no valido: $repository"
  [[ "$workflow" == "$repository/.github/workflows/"*.yml ]] \
    || die "workflow firmante no valido: $workflow"
  [[ "$commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
    || die "commit fuente no valido: $commit"
  [[ "$ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] \
    || die "ref fuente no valida: $ref"
  gh attestation verify "oci://${image}@${digest}" \
    --repo "$repository" \
    --signer-workflow "$workflow" \
    --source-digest "$commit" \
    --source-ref "$ref" \
    --deny-self-hosted-runners >/dev/null
}

inspect_tag_manifest() {
  local image="$1" tag="$2" manifest_file="$3" error_file="$4"
  if ! docker buildx imagetools inspect "${image}:${tag}" \
      --format '{{json .Manifest}}' >"$manifest_file" 2>"$error_file"; then
    cat "$error_file" >&2
    die "no se pudo resolver ${image}:${tag}"
  fi
}

inspect_optional_tag() {
  local image="$1" tag="$2" manifest_file="$3" error_file="$4" status
  if docker buildx imagetools inspect "${image}:${tag}" \
      --format '{{json .Manifest}}' >"$manifest_file" 2>"$error_file"; then
    return 0
  else
    status=$?
  fi
  if is_not_found_error "$error_file"; then
    return 4
  fi
  cat "$error_file" >&2
  die "no se pudo comprobar ${image}:${tag} (codigo $status)"
}

resolve_artifact() {
  require_command gh
  require_command docker
  require_command jq
  require_value GITHUB_REPOSITORY
  require_value GITHUB_REF_NAME
  require_value GITHUB_REF
  require_value GITHUB_SHA
  require_value IMAGE_NAME
  require_value VERSION
  require_value GITHUB_OUTPUT

  local release_error release_file image_error manifest_file
  local release_count release_draft release_immutable candidate_tag digest tag promoted
  release_error="$(temp_file)"
  release_file="$(temp_file)"
  image_error="$(temp_file)"
  manifest_file="$(temp_file)"
  # shellcheck disable=SC2153  # VERSION es una entrada de entorno validada arriba
  candidate_tag="candidate-v${VERSION}-${GITHUB_SHA}"
  [[ "$candidate_tag" =~ ^candidate-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?-([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
    || die "tag de candidato no valido: $candidate_tag"

  if ! gh api --paginate --slurp \
      -H 'X-GitHub-Api-Version: 2026-03-10' \
      "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
      >"$release_file" 2>"$release_error"; then
    cat "$release_error" >&2
    rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
    die "no se pudo consultar las GitHub Releases"
  fi
  release_count="$(jq -r --arg tag "$GITHUB_REF_NAME" \
    '[.[][]? | select(.tag_name == $tag)] | length' "$release_file")"
  case "$release_count" in
    0) ;;
    1)
      release_draft="$(jq -er --arg tag "$GITHUB_REF_NAME" \
        '.[][] | select(.tag_name == $tag) | .draft' "$release_file")"
      release_immutable="$(jq -r --arg tag "$GITHUB_REF_NAME" \
        '.[][] | select(.tag_name == $tag) | (.immutable // false)' "$release_file")"
      if test "$release_draft" != true || test "$release_immutable" = true; then
        rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
        die "la GitHub Release publicada ${GITHUB_REF_NAME} ya existe y bloquea la reejecucion"
      fi
      printf 'Se reanudara el candidato canonico; el draft parcial no se modifica durante build.\n'
      ;;
    *)
      rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
      die "hay ${release_count} releases asociadas a ${GITHUB_REF_NAME}"
      ;;
  esac

  tag="$VERSION"
  promoted=true
  if inspect_optional_tag "$IMAGE_NAME" "$tag" "$manifest_file" "$image_error"; then
    digest="$(manifest_digest "$manifest_file")" || die "el tag final no expone un digest OCI valido"
  else
    test "$?" = 4 || die "estado inesperado al resolver el tag final"
    tag="$candidate_tag"
    promoted=false
    : >"$manifest_file"
    : >"$image_error"
    if inspect_optional_tag "$IMAGE_NAME" "$tag" "$manifest_file" "$image_error"; then
      digest="$(manifest_digest "$manifest_file")" || die "el candidato no expone un digest OCI valido"
    else
      test "$?" = 4 || die "estado inesperado al resolver el candidato"
      {
        echo 'exists=false'
        echo 'digest='
        echo "tag=$candidate_tag"
        echo "candidate_tag=$candidate_tag"
        echo 'promoted=false'
      } >>"$GITHUB_OUTPUT"
      rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
      return 0
    fi
  fi

  require_digest "$digest"
  # Los labels OCI no prueban procedencia. Todo tag reanudable debe estar
  # atestiguado por este workflow, SHA y ref exactos antes de reutilizarse.
  verify_attestation \
    "$IMAGE_NAME" "$digest" "$GITHUB_REPOSITORY" \
    "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
    "$GITHUB_SHA" "$GITHUB_REF"
  {
    echo 'exists=true'
    echo "digest=$digest"
    echo "tag=$tag"
    echo "candidate_tag=$candidate_tag"
    echo "promoted=$promoted"
  } >>"$GITHUB_OUTPUT"
  rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
}

assert_tag_digest() {
  local image="$1" tag="$2" expected_digest="$3"
  local manifest_file error_file actual_digest
  require_command docker
  require_command jq
  require_digest "$expected_digest"
  manifest_file="$(temp_file)"
  error_file="$(temp_file)"
  inspect_tag_manifest "$image" "$tag" "$manifest_file" "$error_file"
  actual_digest="$(manifest_digest "$manifest_file")" || {
    rm -f -- "$manifest_file" "$error_file"
    die "el tag no expone un digest OCI valido"
  }
  rm -f -- "$manifest_file" "$error_file"
  test "$actual_digest" = "$expected_digest" || \
    die "el tag ${image}:${tag} cambio de ${expected_digest} a ${actual_digest}"
}

validate_artifact() { # <image> <tag> <version> <digest> <source> <revision> <license>
  local image="$1" tag="$2" version="$3" digest="$4"
  local expected_source="$5" expected_revision="$6" expected_license="$7"
  local manifest_file error_file image_file tag_digest arch child_digest
  local actual_os actual_arch key expected actual
  require_command docker
  require_command jq
  require_digest "$digest"
  manifest_file="$(temp_file)"
  error_file="$(temp_file)"
  image_file="$(temp_file)"
  inspect_tag_manifest "$image" "$tag" "$manifest_file" "$error_file"
  tag_digest="$(manifest_digest "$manifest_file")" || die "el tag no expone un digest OCI valido"
  test "$tag_digest" = "$digest" || die "el tag ${image}:${tag} no apunta al digest efectivo ${digest}"

  if ! jq -e '
      def digest: type == "string" and test("^sha256:[0-9a-f]{64}$");
      .mediaType == "application/vnd.oci.image.index.v1+json" and
      (.manifests | type == "array") and
      (.manifests as $all |
        [$all[] | select(
          .mediaType == "application/vnd.oci.image.manifest.v1+json" and
          .platform.os == "linux" and
          (.platform.architecture == "amd64" or .platform.architecture == "arm64")
        )] as $images |
        [$all[] | select(
          .mediaType == "application/vnd.oci.image.manifest.v1+json" and
          .platform.os == "unknown" and .platform.architecture == "unknown" and
          .annotations["vnd.docker.reference.type"] == "attestation-manifest"
        )] as $attestations |
        ($all | length == 4) and
        ($all | map(.digest) | all(digest)) and
        ($all | map(.digest) | unique | length == 4) and
        ($images | length == 2) and
        ($images | map(select(.platform.architecture == "amd64")) | length == 1) and
        ($images | map(select(.platform.architecture == "arm64")) | length == 1) and
        ($attestations | length == 2) and
        (($attestations | map(.annotations["vnd.docker.reference.digest"]) | sort) ==
         ($images | map(.digest) | sort))
      )
    ' "$manifest_file" >/dev/null; then
    rm -f -- "$manifest_file" "$error_file" "$image_file"
    die "el indice OCI no contiene exactamente AMD64, ARM64 y una attestation BuildKit por hijo"
  fi

  for arch in amd64 arm64; do
    child_digest="$(jq -er --arg arch "$arch" \
      '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest' \
      "$manifest_file")"
    require_digest "$child_digest"
    if ! docker buildx imagetools inspect "${image}@${child_digest}" \
        --format '{{json .Image}}' >"$image_file" 2>"$error_file"; then
      cat "$error_file" >&2
      rm -f -- "$manifest_file" "$error_file" "$image_file"
      die "no se pudo inspeccionar linux/${arch}@${child_digest}"
    fi
    actual_os="$(jq -er '.os | strings' "$image_file")"
    actual_arch="$(jq -er '.architecture | strings' "$image_file")"
    test "$actual_os/$actual_arch" = "linux/$arch" || \
      die "la configuracion de ${child_digest} declara ${actual_os}/${actual_arch}"

    for key in \
      org.opencontainers.image.version \
      org.opencontainers.image.revision \
      org.opencontainers.image.source \
      org.opencontainers.image.licenses \
      io.ezr43l.cluster-protocol \
      io.ezr43l.image.third-party-notices; do
      case "$key" in
        org.opencontainers.image.version) expected="$version" ;;
        org.opencontainers.image.revision) expected="$expected_revision" ;;
        org.opencontainers.image.source) expected="$expected_source" ;;
        org.opencontainers.image.licenses) expected="$expected_license" ;;
        io.ezr43l.cluster-protocol) expected='v2' ;;
        io.ezr43l.image.third-party-notices) expected='/opt/THIRD_PARTY_NOTICES.md' ;;
      esac
      if ! actual="$(jq -er --arg key "$key" '.config.Labels[$key] | strings' "$image_file")"; then
        rm -f -- "$manifest_file" "$error_file" "$image_file"
        die "falta la etiqueta OCI ${key} en linux/${arch}"
      fi
      test "$actual" = "$expected" || die "etiqueta OCI ${key} invalida en linux/${arch}: ${actual}"
    done
  done
  rm -f -- "$manifest_file" "$error_file" "$image_file"
}

case "${1:-}" in
  resolve)
    test "$#" -eq 1 || die 'uso: release-artifact.sh resolve'
    resolve_artifact
    ;;
  validate)
    test "$#" -eq 8 || die 'uso: release-artifact.sh validate IMAGE TAG VERSION DIGEST SOURCE REVISION LICENSE'
    validate_artifact "$2" "$3" "$4" "$5" "$6" "$7" "$8"
    ;;
  assert)
    test "$#" -eq 4 || die 'uso: release-artifact.sh assert IMAGE TAG DIGEST'
    assert_tag_digest "$2" "$3" "$4"
    ;;
  verify)
    test "$#" -eq 7 || die 'uso: release-artifact.sh verify IMAGE DIGEST REPO WORKFLOW COMMIT REF'
    verify_attestation "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  *)
    die 'subcomando requerido: resolve, validate, assert o verify'
    ;;
esac
