#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ "$(id -u)" != 0 ]]; then
  command -v docker >/dev/null 2>&1 || {
    echo "Docker es necesario para comprobar propietarios root:root." >&2
    exit 1
  }
  docker run --rm \
    -v "$repo_root:/repo:ro" \
    bash:5.3@sha256:a19c811ee9e97fa8a080001d82b8e0ded303f0795cffdb1cbd162731bc8ce208 \
    bash /repo/docker/keepalived/tests/test-compose-storage.sh
  exit
fi

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
helper="$repo_root/prepare-compose-storage.sh"

crear_secretos() { # <directorio>
  local directorio="$1"
  mkdir -p -- "$directorio"
  printf '%s\n' 'VrrpKey1' > "$directorio/keepalived-vrrp.txt"
  printf '%s\n' 'ssssssssssssssssssssssssssssssssssssssss' \
    > "$directorio/keepalived-session-secret.txt"
  printf '%s\n' 'cccccccccccccccccccccccccccccccccccccccc' \
    > "$directorio/keepalived-cluster-token.txt"
}

datos="$test_root/data"
secretos="$test_root/secrets"
crear_secretos "$secretos"
antes="$(sha256sum "$secretos"/*.txt)"
bash "$helper" --fresh-install "$datos" "$secretos" >/dev/null

test "$(stat -c '%u:%g:%a' "$datos")" = '0:0:700'
test "$(stat -c '%u:%g:%a' "$secretos")" = '0:0:700'
test "$antes" = "$(sha256sum "$secretos"/*.txt)"
for fichero in "$secretos"/*.txt; do
  test "$(stat -c '%u:%g:%a:%h' "$fichero")" = '0:0:400:1'
done
for marcador in .bootstrap-pool .bootstrap-security; do
  test "$(stat -c '%u:%g:%a:%h' "$datos/$marcador")" = '0:0:600:1'
  test "$(cat "$datos/$marcador")" = 'fresh-install-v1'
done

# El permiso explícito no es reutilizable ni puede aplicarse sobre datos.
if bash "$helper" --fresh-install "$datos" "$secretos" >/dev/null 2>&1; then
  echo "Se ha reutilizado --fresh-install sobre un árbol no vacío." >&2
  exit 1
fi
# Sin consumo por el runtime, los marcadores también bloquean una preparación
# ordinaria: no se disfraza un alta parcial como una actualización.
if bash "$helper" "$datos" "$secretos" >/dev/null 2>&1; then
  echo "Se ha aceptado un bootstrap residual como actualización." >&2
  exit 1
fi
rm -f -- "$datos/.bootstrap-pool" "$datos/.bootstrap-security"

printf '%s\n' \
  '{"capabilities":["pool-causal-v2","security-causal-v2"],"nodos":["node-a","node-b"],"schema":1}' \
  > "$datos/.cluster-protocol-v2"
chmod 0644 "$datos/.cluster-protocol-v2"
bash "$helper" "$datos" "$secretos" >/dev/null
test "$(stat -c '%u:%g:%a:%h' "$datos/.cluster-protocol-v2")" = '0:0:600:1'

# Un árbol de secretos no dedicado se rechaza antes de apropiarse del mismo.
scope_dir="$test_root/scope-sentinel"
crear_secretos "$scope_dir"
printf '%s\n' 'no-tocar' > "$scope_dir/otro-fichero"
chmod 0755 "$scope_dir"
chown 1234:1234 "$scope_dir"
modo_antes="$(stat -c '%u:%g:%a' "$scope_dir")"
if bash "$helper" "$test_root/data-sentinel" "$scope_dir" >/dev/null 2>&1; then
  echo "Se ha aceptado un SECRETS_DIR que no era dedicado." >&2
  exit 1
fi
test "$(stat -c '%u:%g:%a' "$scope_dir")" = "$modo_antes"
test ! -e "$test_root/data-sentinel"

# Los aliases por enlace simbólico, hardlink y anidamiento se rechazan.
destino="$test_root/secretos-reales"
crear_secretos "$destino"
ln -s "$destino" "$test_root/secretos-enlace"
if bash "$helper" "$test_root/data-link" "$test_root/secretos-enlace" \
    >/dev/null 2>&1; then
  echo "Se ha aceptado un SECRETS_DIR simbólico." >&2
  exit 1
fi

hardlinks="$test_root/secretos-hardlink"
crear_secretos "$hardlinks"
ln "$hardlinks/keepalived-vrrp.txt" "$test_root/alias-vrrp"
if bash "$helper" "$test_root/data-hardlink" "$hardlinks" >/dev/null 2>&1; then
  echo "Se ha aceptado un secreto con hardlink." >&2
  exit 1
fi

anidado="$test_root/data-nested"
crear_secretos "$anidado/secrets"
if bash "$helper" "$anidado" "$anidado/secrets" >/dev/null 2>&1; then
  echo "Se han aceptado secretos dentro del volumen /datos." >&2
  exit 1
fi

invalidos="$test_root/secretos-invalidos"
crear_secretos "$invalidos"
: > "$invalidos/keepalived-session-secret.txt"
if bash "$helper" "$test_root/data-invalid" "$invalidos" >/dev/null 2>&1; then
  echo "Se ha aceptado un secreto Compose vacío." >&2
  exit 1
fi
test ! -e "$test_root/data-invalid"

iguales="$test_root/secretos-iguales"
crear_secretos "$iguales"
cp "$iguales/keepalived-session-secret.txt" \
  "$iguales/keepalived-cluster-token.txt"
if bash "$helper" "$test_root/data-equal" "$iguales" >/dev/null 2>&1; then
  echo "Se han aceptado secretos de sesión y clúster iguales." >&2
  exit 1
fi

marker_hardlink_data="$test_root/data-marker-hardlink"
mkdir -p "$marker_hardlink_data"
printf '%s\n' marker > "$test_root/marker-target"
ln "$test_root/marker-target" "$marker_hardlink_data/.cluster-protocol-v2"
if bash "$helper" "$marker_hardlink_data" "$secretos" >/dev/null 2>&1; then
  echo "Se ha aceptado .cluster-protocol-v2 con hardlink." >&2
  exit 1
fi

printf '%s\n' 'compose storage tests: OK'
