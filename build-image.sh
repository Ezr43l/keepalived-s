#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VERSION="$(tr -d ' \r\n' < VERSION)"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
  echo "VERSION '$VERSION' no cumple MAYOR.MENOR.PARCHE[-rc.N]" >&2
  exit 2
fi

IMAGE_REPOSITORY="${FIP_IMAGE_REPOSITORY:-${IMAGE_REPOSITORY:-keepalived}}"
IMAGE="$IMAGE_REPOSITORY:$VERSION"
SOURCE_URL="${SOURCE_URL:-https://github.com/Ezr43l/keepalived-s}"
LICENSE_SPDX="${LICENSE_SPDX:-Apache-2.0}"
PLATFORM="${PLATFORM:-}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VCS_REF="$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"

# Este script es deliberadamente incapaz de publicar. La unica ruta autorizada
# para escribir en GHCR es el workflow de release protegido y auditado.
if [[ -n "${PUBLISH+x}" || -n "${PLATFORMS+x}" ]]; then
  echo "PUBLISH y PLATFORMS no estan admitidos: build-image.sh solo carga una imagen local" >&2
  exit 2
fi

comun=(
  --pull
  --file docker/keepalived/Dockerfile
  --build-arg "FIP_APP_VERSION=$VERSION"
  --build-arg "SOURCE_URL=$SOURCE_URL"
  --build-arg "BUILD_DATE=$BUILD_DATE"
  --build-arg "VCS_REF=$VCS_REF"
  --build-arg "LICENSE=$LICENSE_SPDX"
  --tag "$IMAGE"
)

plataforma=()
[[ -n "$PLATFORM" ]] && plataforma=(--platform "$PLATFORM")
docker buildx build "${comun[@]}" "${plataforma[@]}" --load .
echo "Imagen local construida y probada: $IMAGE"
