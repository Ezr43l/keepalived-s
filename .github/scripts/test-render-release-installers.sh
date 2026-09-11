#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

version=1.0.2
image=ghcr.io/ezr43l/keepalived-s
digest="sha256:$(printf 'a%.0s' {1..64})"
python3 "$repo_root/.github/scripts/render-release-installers.py" \
  --root "$repo_root" --output "$test_root" \
  --image "$image" --version "$version" --digest "$digest"

xml="$test_root/my-Keepalived-$version.xml"
compose="$test_root/docker-compose-$version.yml"
test -f "$xml" -a -f "$compose"
test "$(grep -Fc "<Repository>$image@$digest</Repository>" "$xml")" = 1
test "$(grep -Fc "<TemplateURL>https://github.com/Ezr43l/keepalived-s/releases/download/v$version/my-Keepalived-$version.xml</TemplateURL>" "$xml")" = 1
test "$(grep -Fc "<Icon>https://raw.githubusercontent.com/Ezr43l/keepalived-s/v$version/logo/icono.png</Icon>" "$xml")" = 1
if grep -Fq '<TemplateURL>https://raw.githubusercontent.com/' "$xml"; then
  echo 'TemplateURL no apunta al asset de la release inmutable.' >&2
  exit 1
fi
test "$(grep -Fc "image: $image@$digest" "$compose")" = 1
if grep -Eq '^[[:space:]]+build:' "$compose"; then
  echo 'El Compose de release conserva un build local no verificable.' >&2
  exit 1
fi
python3 -c 'import sys, xml.etree.ElementTree as E; E.parse(sys.argv[1])' "$xml"
docker compose --env-file "$repo_root/.env.example" -f "$compose" config --quiet

if python3 "$repo_root/.github/scripts/render-release-installers.py" \
    --root "$repo_root" --output "$test_root/invalid" \
    --image "$image" --version "$version" --digest sha256:1234 \
    >/dev/null 2>&1; then
  echo 'El renderer aceptó un digest truncado.' >&2
  exit 1
fi

printf '%s\n' 'release installer rendering tests: OK'
