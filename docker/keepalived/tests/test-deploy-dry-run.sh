#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
test_root="$(mktemp -d)"
secrets_dir="$test_root/secrets"
manifest="$test_root/manifiesto.local.sh"
output="$test_root/output.txt"
generated_dir="$test_root/generated-secrets"
symlink_dir="$test_root/symlink-secrets"
dry_data_dir="$test_root/dry-data-no-creado"
cleanup_test_root() {
  find "$test_root" -depth -delete
}
trap cleanup_test_root EXIT
mkdir -p "$secrets_dir"
chmod 0700 "$secrets_dir"

probar_almacen_persistente() {
  local raiz datos nuevo suma_antes suma_despues modo_objetivo nombre caso
  local escritor_serializado semilla semilla_alternativa huella huella_alternativa
  local semilla_grande secretos_remotos secretos_antes auditoria_secretos
  local -a vips_extraidas=()
  set -euo pipefail
  raiz="$(mktemp -d)"

  datos="$raiz/existente"
  mkdir -p "$datos"
  printf '%s\n' 'pool-sentinel' > "$datos/pool.json"
  printf '%s\n' 'pool-lock-sentinel' > "$datos/pool.json.lock"
  printf '%s\n' 'security-sentinel' > "$datos/security.json"
  printf '%s\n' 'security-lock-sentinel' > "$datos/security.json.lock"
  printf '%s\n' 'config-sentinel' > "$datos/keepalived.conf"
  chmod 0777 "$datos"
  chmod 0666 "$datos"/*.json "$datos/keepalived.conf"
  suma_antes="$(sha256sum "$datos"/pool.json "$datos"/pool.json.lock \
    "$datos"/security.json "$datos"/security.json.lock "$datos"/keepalived.conf)"

  preparar_almacen_persistente "$datos"
  test "$(stat -c %u:%g:%a "$datos")" = "0:0:700"
  for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf; do
    test -f "$datos/$nombre"
    test ! -L "$datos/$nombre"
    test "$(stat -c %u:%g:%a "$datos/$nombre")" = "0:0:600"
  done
  suma_despues="$(sha256sum "$datos"/pool.json "$datos"/pool.json.lock \
    "$datos"/security.json "$datos"/security.json.lock "$datos"/keepalived.conf)"
  test "$suma_antes" = "$suma_despues"

  escritor_serializado="$(declare -f escribir_configuracion_atomica)"
  printf '%s\n' 'configuracion-nueva' | bash -c \
    "set -eu; $escritor_serializado; escribir_configuracion_atomica \
      '$datos' '$datos/keepalived.conf'"
  test "$(<"$datos/pool.json")" = 'pool-sentinel'
  test "$(<"$datos/security.json")" = 'security-sentinel'
  test "$(<"$datos/keepalived.conf")" = 'configuracion-nueva'
  test "$(stat -c %u:%g:%a "$datos/keepalived.conf")" = "0:0:600"
  suma_antes="$(sha256sum "$datos/keepalived.conf")"
  if printf '' \
      | escribir_configuracion_atomica "$datos" "$datos/keepalived.conf" \
        >/dev/null 2>&1; then
    echo 'Se aceptó una configuración temporal vacía' >&2
    return 1
  fi
  test "$suma_antes" = "$(sha256sum "$datos/keepalived.conf")"
  if compgen -G "$datos/.keepalived.conf.*" >/dev/null; then
    echo 'Quedó un temporal de configuración tras un fallo' >&2
    return 1
  fi

  caso="$raiz/escritor-enlace"
  mkdir -p "$caso"
  chown 0:0 "$caso"
  chmod 0700 "$caso"
  printf '%s\n' 'destino-intacto' > "$raiz/destino-config"
  ln -s "$raiz/destino-config" "$caso/keepalived.conf"
  if printf '%s\n' 'no-escribir' \
      | escribir_configuracion_atomica "$caso" "$caso/keepalived.conf" \
        >/dev/null 2>&1; then
    echo 'El escritor atómico aceptó keepalived.conf simbólico' >&2
    return 1
  fi
  test "$(<"$raiz/destino-config")" = 'destino-intacto'

  nuevo="$raiz/nuevo"
  {
    declare -f preparar_almacen_persistente
    # shellcheck disable=SC2016  # $1 debe expandirse en el bash receptor
    printf '%s\n' 'set -euo pipefail' 'preparar_almacen_persistente "$1"'
  } | bash -s -- "$nuevo"
  test -d "$nuevo"
  test ! -L "$nuevo"
  test "$(stat -c %u:%g:%a "$nuevo")" = "0:0:700"

  semilla="$raiz/semilla.json"
  semilla_alternativa="$raiz/semilla-alternativa.json"
  printf '%s\n' '{"semilla":"inicial"}' > "$semilla"
  printf '%s\n' '{"semilla":"no-sobrescribir"}' > "$semilla_alternativa"
  huella="$(sha256sum "$semilla")"
  huella="${huella%% *}"
  huella_alternativa="$(sha256sum "$semilla_alternativa")"
  huella_alternativa="${huella_alternativa%% *}"
  cat "$semilla" | instalar_semilla_pool "$nuevo" "$huella" >/dev/null
  test "$(sha256sum "$nuevo/pool.json" | cut -d' ' -f1)" = "$huella"
  test "$(stat -c %u:%g:%a "$nuevo/pool.json")" = "0:0:600"

  # Una segunda instalación, aunque traiga otros bytes, jamás sustituye el
  # registro existente ni sus datos.
  cat "$semilla_alternativa" \
    | instalar_semilla_pool "$nuevo" "$huella_alternativa" >/dev/null
  test "$(sha256sum "$nuevo/pool.json" | cut -d' ' -f1)" = "$huella"
  test "$(<"$nuevo/pool.json")" = '{"semilla":"inicial"}'

  caso="$raiz/semilla-vacia"
  preparar_almacen_persistente "$caso"
  huella="$(printf '' | sha256sum)"
  huella="${huella%% *}"
  if printf '' | instalar_semilla_pool "$caso" "$huella" >/dev/null 2>&1; then
    echo 'Se instaló una semilla de pool vacía' >&2
    return 1
  fi
  test ! -e "$caso/pool.json"
  if compgen -G "$caso/.pool.seed.*" >/dev/null; then
    echo 'Quedó una semilla parcial vacía' >&2
    return 1
  fi

  caso="$raiz/semilla-incompleta"
  preparar_almacen_persistente "$caso"
  if cat "$semilla" | instalar_semilla_pool "$caso" \
      '0000000000000000000000000000000000000000000000000000000000000000' \
      >/dev/null 2>&1; then
    echo 'Se instaló una semilla con huella incorrecta' >&2
    return 1
  fi
  test ! -e "$caso/pool.json"
  if compgen -G "$caso/.pool.seed.*" >/dev/null; then
    echo 'Quedó una semilla parcial tras fallo de integridad' >&2
    return 1
  fi

  caso="$raiz/semilla-mayor-512-kib"
  preparar_almacen_persistente "$caso"
  semilla_grande="$raiz/semilla-grande.json"
  head -c $((512 * 1024 + 1)) /dev/zero | tr '\0' x > "$semilla_grande"
  huella="$(sha256sum "$semilla_grande")"
  huella="${huella%% *}"
  if cat "$semilla_grande" | instalar_semilla_pool "$caso" "$huella" \
      >/dev/null 2>&1; then
    echo 'Se instaló una semilla mayor de 512 KiB' >&2
    return 1
  fi
  test ! -e "$caso/pool.json"
  if compgen -G "$caso/.pool.seed.*" >/dev/null; then
    echo 'Quedó una semilla parcial tras superar 512 KiB' >&2
    return 1
  fi

  mkdir -p "$raiz/destino-directo"
  ln -s "$raiz/destino-directo" "$raiz/enlace-directo"
  if preparar_almacen_persistente "$raiz/enlace-directo" >/dev/null 2>&1; then
    echo 'Se aceptó FIP_DATA_DIR como enlace simbólico' >&2
    return 1
  fi

  mkdir -p "$raiz/padre-real"
  ln -s "$raiz/padre-real" "$raiz/padre-enlace"
  if preparar_almacen_persistente "$raiz/padre-enlace/datos" \
      >/dev/null 2>&1; then
    echo 'Se aceptó un componente simbólico de FIP_DATA_DIR' >&2
    return 1
  fi
  test ! -e "$raiz/padre-real/datos"

  for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
      .cluster-protocol-v2; do
    caso="$raiz/enlace-$nombre"
    mkdir -p "$caso"
    chmod 0755 "$caso"
    printf '%s\n' 'objetivo-intacto' > "$raiz/objetivo-$nombre"
    chmod 0644 "$raiz/objetivo-$nombre"
    modo_objetivo="$(stat -c %a "$raiz/objetivo-$nombre")"
    ln -s "$raiz/objetivo-$nombre" "$caso/$nombre"
    if preparar_almacen_persistente "$caso" >/dev/null 2>&1; then
      echo "Se aceptó $nombre como enlace simbólico" >&2
      return 1
    fi
    test "$(<"$raiz/objetivo-$nombre")" = 'objetivo-intacto'
    test "$(stat -c %a "$raiz/objetivo-$nombre")" = "$modo_objetivo"
    test "$(stat -c %a "$caso")" = "755"
  done

  caso="$raiz/hardlink-pool"
  mkdir -p "$caso"
  printf '%s\n' 'objetivo-hardlink-intacto' > "$raiz/objetivo-hardlink"
  chmod 0644 "$raiz/objetivo-hardlink"
  ln "$raiz/objetivo-hardlink" "$caso/pool.json"
  modo_objetivo="$(stat -c %u:%g:%a "$raiz/objetivo-hardlink")"
  if preparar_almacen_persistente "$caso" >/dev/null 2>&1; then
    echo "Se aceptó pool.json con hardlink" >&2
    return 1
  fi
  test "$(stat -c %u:%g:%a "$raiz/objetivo-hardlink")" = "$modo_objetivo"

  for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
      .cluster-protocol-v2; do
    caso="$raiz/no-regular-$nombre"
    mkdir -p "$caso/$nombre"
    if preparar_almacen_persistente "$caso" >/dev/null 2>&1; then
      echo "Se aceptó $nombre como directorio" >&2
      return 1
    fi
  done

  caso="$raiz/no-regular-config"
  mkdir -p "$caso"
  mkfifo "$caso/keepalived.conf"
  if preparar_almacen_persistente "$caso" >/dev/null 2>&1; then
    echo 'Se aceptó keepalived.conf como FIFO' >&2
    return 1
  fi

  if preparar_almacen_persistente 'ruta-relativa' >/dev/null 2>&1 \
      || preparar_almacen_persistente '/boot/floating-ip' >/dev/null 2>&1 \
      || preparar_almacen_persistente "$raiz/./dot-no-crear" >/dev/null 2>&1 \
      || preparar_almacen_persistente "$raiz/sub/../parent-no-crear" \
        >/dev/null 2>&1; then
    echo 'Se aceptó una ruta de datos relativa, no normalizada o bajo /boot' >&2
    return 1
  fi
  test ! -e "$raiz/dot-no-crear"
  test ! -e "$raiz/parent-no-crear"

  caso="$raiz/control-v2"
  preparar_almacen_persistente "$caso"
  printf '%s\n' \
    '{"capabilities":["pool-causal-v2","security-causal-v2"],"nodos":["node-a","node-b"],"schema":1}' \
    > "$caso/.cluster-protocol-v2"
  chmod 0600 "$caso/.cluster-protocol-v2"
  huella="$(sha256sum "$caso/.cluster-protocol-v2")"; huella="${huella%% *}"
  docker() { return 1; }
  test "$(auditar_control_remoto "$caso" inexistente "$huella" v2)" \
    = 'marker=present'
  if auditar_control_remoto "$caso" inexistente \
      '0000000000000000000000000000000000000000000000000000000000000000' \
      v2 >/dev/null 2>&1; then
    echo 'Se aceptó un marcador v2 de otra topología' >&2
    return 1
  fi
  if auditar_control_remoto "$caso" inexistente "$huella" legacy \
      >/dev/null 2>&1; then
    echo 'Se aceptó un marcador v2 junto a un contenedor legacy' >&2
    return 1
  fi

  plantilla_prueba="$raiz/plantilla-v2.xml"
  referencia_prueba="registry.example/floating-ip@sha256:$(printf '%064d' 7)"
  printf '<Container>\n  <Repository>%s</Repository>\n</Container>\n' \
    "$referencia_prueba" > "$plantilla_prueba"
  docker() {
    if [[ "$1" == inspect && "$*" != *--format* ]]; then return 0; fi
    if [[ "$1 $2" == 'inspect --format' && "$3" == '{{.Image}}' ]]; then
      printf 'sha256:%064d\n' 8
    elif [[ "$1 $2" == 'image inspect' && "$*" == *org.opencontainers.image.revision* ]]; then
      printf '%040d\n' 9
    elif [[ "$1 $2" == 'image inspect' && "$*" == *org.opencontainers.image.version* ]]; then
      printf '%s\n' 1.0.2
    elif [[ "$1 $2" == 'image inspect' && "$*" == *io.ezr43l.cluster-protocol* ]]; then
      printf '%s\n' v2
    elif [[ "$1 $2" == 'image inspect' && "$*" == *RepoDigests* ]]; then
      printf '%s\n' "$referencia_prueba"
    else
      return 1
    fi
  }
  artefacto="$(auditar_artefacto_actual_remoto \
    Keepalived "$plantilla_prueba" v2 1.0.2)"
  [[ "$artefacto" == artifact=v2\;revision=*\;digest="$referencia_prueba"\;image=sha256:* ]]
  sed -i 's/@sha256:[0-9]*/:1.0.2/' "$plantilla_prueba"
  if auditar_artefacto_actual_remoto Keepalived "$plantilla_prueba" v2 1.0.2 \
      >/dev/null 2>&1; then
    echo 'Se aceptó una plantilla v2 sin referencia inmutable' >&2
    return 1
  fi

  printf '%s\n' fresh-install-v1 > "$caso/.bootstrap-pool"
  chmod 0600 "$caso/.bootstrap-pool"
  if preparar_almacen_persistente "$caso" >/dev/null 2>&1; then
    echo 'Se aceptó un marcador bootstrap residual durante una actualización' >&2
    return 1
  fi
  rm -f -- "$caso/.bootstrap-pool"

  caso="$raiz/config-vips"
  cat > "$caso" <<'CONF'
# nota: ip del nodo 192.0.2.10
{"descripcion":"ip del nodo 192.0.2.11"}
    192.0.2.100/24 dev eth0
    192.0.2.101/24 dev eth1
CONF
  mapfile -t vips_extraidas < <(extraer_vips_config "$caso" 24 eth0)
  test "${#vips_extraidas[@]}" -eq 1
  test "${vips_extraidas[0]}" = '192.0.2.100'

  secretos_remotos="$raiz/secretos-remotos"
  printf '%s\n%s\n%s\n' \
    'VrrpKey1' \
    'ssssssssssssssssssssssssssssssssssssssss' \
    'cccccccccccccccccccccccccccccccccccccccc' \
    | instalar_secretos_remotos "$secretos_remotos"
  test "$(stat -c %u:%g:%a "$secretos_remotos")" = '0:0:700'
  for nombre in vrrp-auth.txt session-secret.txt cluster-token.txt; do
    test "$(stat -c %u:%g:%a:%h "$secretos_remotos/$nombre")" = '0:0:400:1'
  done
  secretos_antes="$(sha256sum "$secretos_remotos"/*.txt)"
  printf '%s\n%s\n%s\n' \
    'VrrpKey1' \
    'ssssssssssssssssssssssssssssssssssssssss' \
    'cccccccccccccccccccccccccccccccccccccccc' \
    | instalar_secretos_remotos "$secretos_remotos"
  test "$secretos_antes" = "$(sha256sum "$secretos_remotos"/*.txt)"
  if printf '%s\n%s\n%s\n' \
      'OtraKey' \
      'ssssssssssssssssssssssssssssssssssssssss' \
      'cccccccccccccccccccccccccccccccccccccccc' \
      | instalar_secretos_remotos "$secretos_remotos" >/dev/null 2>&1; then
    echo 'Se aceptó rotar un secreto remoto durante el despliegue normal' >&2
    return 1
  fi
  test "$secretos_antes" = "$(sha256sum "$secretos_remotos"/*.txt)"
  auditoria_secretos="$(auditar_secretos_remotos "$secretos_remotos" inexistente)"
  test "$(printf '%s\n' "$auditoria_secretos" | wc -l)" -eq 3
  test "$(printf '%s\n' "$auditoria_secretos" | grep -c '=missing')" -eq 0
  chmod 0600 "$secretos_remotos/session-secret.txt"
  if auditar_secretos_remotos "$secretos_remotos" inexistente \
      >/dev/null 2>&1; then
    echo 'La auditoría aceptó un secreto remoto que no era root:root 0400' >&2
    return 1
  fi
  chmod 0400 "$secretos_remotos/session-secret.txt"
  chmod 0755 "$secretos_remotos"
  if auditar_secretos_remotos "$secretos_remotos" inexistente \
      >/dev/null 2>&1; then
    echo 'La auditoría aceptó el padre remoto sin root:root 0700' >&2
    return 1
  fi
  chmod 0700 "$secretos_remotos"
  ln "$secretos_remotos/cluster-token.txt" "$raiz/cluster-token-hardlink"
  if auditar_secretos_remotos "$secretos_remotos" inexistente \
      >/dev/null 2>&1; then
    echo 'La auditoría aceptó un secreto remoto con hardlink' >&2
    return 1
  fi
  rm -f -- "$raiz/cluster-token-hardlink"

  instalar_marcadores_bootstrap "$datos"
  for nombre in .bootstrap-pool .bootstrap-security; do
    test "$(stat -c %u:%g:%a:%h "$datos/$nombre")" = '0:0:600:1'
    test "$(<"$datos/$nombre")" = 'fresh-install-v1'
  done
  if instalar_marcadores_bootstrap "$datos" >/dev/null 2>&1; then
    echo 'Se reutilizaron marcadores de bootstrap remotos' >&2
    return 1
  fi

  find "$raiz" -depth -delete
}

# Las comprobaciones root:root se ejecutan realmente. En runners sin privilegios
# se usa un contenedor efímero; no se conecta a ningún host ni monta rutas reales.
storage_lib="$test_root/storage-lib.sh"
sed '/^REPO_ROOT=/,$d' "$repo_root/deploy-floating-ip.sh" > "$storage_lib"
grep -Fq 'preparar_almacen_persistente()' "$storage_lib"
grep -Fq 'escribir_configuracion_atomica()' "$storage_lib"
grep -Fq 'generar_semilla_pool()' "$storage_lib"
grep -Fq 'instalar_semilla_pool()' "$storage_lib"
grep -Fq 'extraer_vips_config()' "$storage_lib"
grep -Fq 'instalar_secretos_remotos()' "$storage_lib"
grep -Fq 'auditar_secretos_remotos()' "$storage_lib"
grep -Fq 'auditar_control_remoto()' "$storage_lib"
grep -Fq 'auditar_artefacto_actual_remoto()' "$storage_lib"
# shellcheck source=/dev/null
source "$storage_lib"
if [[ "$(id -u)" == 0 ]]; then
  probar_almacen_persistente
else
  command -v docker >/dev/null 2>&1 || {
    echo 'Docker es necesario para comprobar propietario root:root' >&2
    exit 1
  }
  {
    declare -f preparar_almacen_persistente
    declare -f escribir_configuracion_atomica
    declare -f instalar_semilla_pool
    declare -f extraer_vips_config
    declare -f instalar_secretos_remotos
    declare -f auditar_secretos_remotos
    declare -f auditar_control_remoto
    declare -f auditar_artefacto_actual_remoto
    declare -f instalar_marcadores_bootstrap
    declare -f probar_almacen_persistente
    printf '%s\n' 'probar_almacen_persistente'
  } | docker run --rm -i --entrypoint bash \
    bash:5.3@sha256:a19c811ee9e97fa8a080001d82b8e0ded303f0795cffdb1cbd162731bc8ce208 \
    -s
fi

bash "$repo_root/provision-security-secrets.sh" "$generated_dir" >/dev/null
test "$(stat -c %a "$generated_dir")" = "700"
test "$(stat -c %a "$generated_dir/keepalived-vrrp.txt")" = "600"
test "$(stat -c %a "$generated_dir/keepalived-session-secret.txt")" = "600"
test "$(stat -c %a "$generated_dir/keepalived-cluster-token.txt")" = "600"
generated_vrrp="$(<"$generated_dir/keepalived-vrrp.txt")"
[[ "$generated_vrrp" =~ ^[A-Za-z0-9_-]{8}$ ]]
before="$(sha256sum "$generated_dir"/*.txt)"
bash "$repo_root/provision-security-secrets.sh" "$generated_dir" >/dev/null
test "$before" = "$(sha256sum "$generated_dir"/*.txt)"

invalid_generated="$test_root/generated-invalid"
mkdir -p "$invalid_generated"
chmod 0700 "$invalid_generated"
: > "$invalid_generated/keepalived-vrrp.txt"
if bash "$repo_root/provision-security-secrets.sh" "$invalid_generated" \
    >/dev/null 2>&1; then
  echo 'El generador ha conservado un secreto existente vacío' >&2
  exit 1
fi

equal_generated="$test_root/generated-equal"
mkdir -p "$equal_generated"
chmod 0700 "$equal_generated"
printf '%s\n' 'VrrpKey1' > "$equal_generated/keepalived-vrrp.txt"
printf '%s\n' 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' \
  > "$equal_generated/keepalived-session-secret.txt"
cp "$equal_generated/keepalived-session-secret.txt" \
  "$equal_generated/keepalived-cluster-token.txt"
if bash "$repo_root/provision-security-secrets.sh" "$equal_generated" \
    >/dev/null 2>&1; then
  echo 'El generador ha aceptado secretos de sesión y clúster iguales' >&2
  exit 1
fi

mkdir -p "$symlink_dir"
chmod 0700 "$symlink_dir"
ln -s "$generated_dir/keepalived-vrrp.txt" "$symlink_dir/keepalived-vrrp.txt"
if bash "$repo_root/provision-security-secrets.sh" "$symlink_dir" \
    >/dev/null 2>&1; then
  echo 'El generador ha aceptado un destino de secreto simbólico' >&2
  exit 1
fi

wide_dir="$test_root/no-apropiar-directorio-amplio"
mkdir -p "$wide_dir"
chmod 0755 "$wide_dir"
if bash "$repo_root/provision-security-secrets.sh" "$wide_dir" \
    >/dev/null 2>&1; then
  echo 'El generador ha cambiado implícitamente un directorio no privado' >&2
  exit 1
fi
test "$(stat -c %a "$wide_dir")" = '755'
test -z "$(find "$wide_dir" -mindepth 1 -maxdepth 1 -print -quit)"

hardlink_secrets="$test_root/hardlink-secrets"
mkdir -p "$hardlink_secrets"
chmod 0700 "$hardlink_secrets"
printf '%s\n' 'objetivo-intacto' > "$test_root/secret-hardlink-target"
chmod 0644 "$test_root/secret-hardlink-target"
ln "$test_root/secret-hardlink-target" \
  "$hardlink_secrets/keepalived-vrrp.txt"
if bash "$repo_root/provision-security-secrets.sh" "$hardlink_secrets" \
    >/dev/null 2>&1; then
  echo 'El generador ha aceptado un fichero de secreto con hardlink' >&2
  exit 1
fi
test "$(stat -c %a "$test_root/secret-hardlink-target")" = '644'

printf '%s\n' 'testpass' > "$secrets_dir/keepalived-vrrp.txt"
printf '%s\n' 'ssssssssssssssssssssssssssssssssssssssss' \
  > "$secrets_dir/keepalived-session-secret.txt"
printf '%s\n' 'cccccccccccccccccccccccccccccccccccccccc' \
  > "$secrets_dir/keepalived-cluster-token.txt"
printf '%s\n' 'not-a-real-private-key' > "$secrets_dir/ssh_key_node_a"
printf '%s\n' 'not-a-real-private-key' > "$secrets_dir/ssh_key_node_b"
chmod 0600 "$secrets_dir"/*

cat > "$manifest" <<'MANIFEST'
DHCP_DESDE=200
VIP_PREFIJO=24
NODOS=(
  "node-a:192.0.2.10:eth0:150:ssh_key_node_a"
  "node-b:192.0.2.11:eth0:100:ssh_key_node_b"
)
DIRECCIONES=(
  "service-a:192.0.2.100:51:8080:/health:node-a"
  "service-b:192.0.2.99:52:9090:/ready:-"
)
PREEMPT_DELAY=45
MANIFEST

seed_file="$test_root/pool-seed.json"
seed_repeat="$test_root/pool-seed-repeat.json"
seed_reordered="$test_root/pool-seed-reordered.json"
seed_timestamp="2026-01-02T03:04:05+00:00"
# shellcheck source=/dev/null
source "$manifest"
generar_semilla_pool "$seed_timestamp" "$DHCP_DESDE" \
  "${DIRECCIONES[@]}" > "$seed_file"
generar_semilla_pool "$seed_timestamp" "$DHCP_DESDE" \
  "${DIRECCIONES[@]}" > "$seed_repeat"
generar_semilla_pool "$seed_timestamp" "$DHCP_DESDE" \
  "${DIRECCIONES[1]}" "${DIRECCIONES[0]}" > "$seed_reordered"
test "$(sha256sum "$seed_file" | cut -d' ' -f1)" \
  = "$(sha256sum "$seed_repeat" | cut -d' ' -f1)"
test "$(sha256sum "$seed_file" | cut -d' ' -f1)" \
  = "$(sha256sum "$seed_reordered" | cut -d' ' -f1)"

PYTHONPATH="$repo_root/docker/keepalived/panel" \
  python3 - "$seed_file" "$seed_timestamp" <<'PY'
import json
import sys

import pool

with open(sys.argv[1], "r", encoding="utf-8") as archivo:
    semilla = json.load(archivo)
marca = sys.argv[2]
esperada = {
    "version": 1,
    "actualizado": marca,
    "dhcp_desde": 200,
    "mantenimiento": [],
    "reclamaciones": {},
    "direcciones": [
        {
            "ip": "192.0.2.99", "vrid": 52, "estado": "en_uso",
            "servicio": "service-b", "descripcion": "", "puertos": [9090],
            "chequeo": {"puerto": 9090, "ruta": "/ready"},
            "preferente": None, "notas": "", "creada": marca,
        },
        {
            "ip": "192.0.2.100", "vrid": 51, "estado": "en_uso",
            "servicio": "service-a", "descripcion": "", "puertos": [8080],
            "chequeo": {"puerto": 8080, "ruta": "/health"},
            "preferente": "node-a", "notas": "", "creada": marca,
        },
    ],
}
assert semilla == esperada
assert "revision" not in semilla
assert semilla["direcciones"]
problemas = pool.validar(semilla)
assert problemas == [], problemas
assert len(open(sys.argv[1], "rb").read()) <= 512 * 1024
assert len(pool.Pool.huella(semilla)) == 64
PY

test ! -e "$dry_data_dir"
FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
  FIP_DATA_DIR="$dry_data_dir" \
  bash "$repo_root/deploy-floating-ip.sh" --dry-run > "$output"
test ! -e "$dry_data_dir"

grep -Fq '(simulacion: no se ha tocado ningun nodo)' "$output"
grep -Fq 'auth_pass ********' "$output"
if grep -Fq 'testpass' "$output" || \
   grep -Fq 'ssssssssssssssssssssssssssssssssssssssss' "$output" || \
   grep -Fq 'cccccccccccccccccccccccccccccccccccccccc' "$output"; then
  echo 'La simulación ha expuesto un secreto' >&2
  exit 1
fi

chmod 0644 "$secrets_dir/ssh_key_node_a"
if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una clave SSH local con permisos amplios' >&2
  exit 1
fi
grep -Fq 'clave SSH de node-a debe ser propia, canónica, 0600 y sin enlaces' "$output"
chmod 0600 "$secrets_dir/ssh_key_node_a"

chmod 0644 "$secrets_dir/keepalived-session-secret.txt"
if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó un secreto local con permisos amplios' >&2
  exit 1
fi
grep -Fq 'fichero local de SESSION_SECRET debe ser propio, canónico, 0600' "$output"
chmod 0600 "$secrets_dir/keepalived-session-secret.txt"

if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run --fresh-install node-a \
    >/dev/null 2>&1; then
  echo 'Se aceptó --fresh-install para un subconjunto del clúster' >&2
  exit 1
fi

if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    FIP_DATA_DIR=/mnt/user/appdata/floating-ip \
    FIP_REMOTE_SECRETS_DIR=/mnt/user/secrets/floating-ip \
    FIP_TRANSACTION_ROOT=/mnt/user/secrets/floating-ip/transactions \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó un journal anidado en el árbol de secretos remotos' >&2
  exit 1
fi
grep -Fq 'Datos, secretos, plantillas y journal deben ser árboles disjuntos' "$output"
FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
  bash "$repo_root/deploy-floating-ip.sh" --dry-run --fresh-install > "$output"
grep -Fq 'la vaciedad remota para --fresh-install aún no se ha comprobado' "$output"

collision_manifest="$test_root/manifiesto-colision-vrrp.sh"
cp "$manifest" "$collision_manifest"
cat >> "$collision_manifest" <<'COLLISION'
DIRECCIONES=(
  "foo-bar:192.0.2.100:51:8080:/health:-"
  "foo_bar:192.0.2.99:52:9090:/ready:-"
)
COLLISION
if FIP_MANIFIESTO="$collision_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptaron servicios que colisionan en el identificador VRRP' >&2
  exit 1
fi
grep -Fq 'mismo identificador VRRP: FOO_BAR' "$output"

leading_zero_manifest="$test_root/manifiesto-octeto-cero.sh"
cp "$manifest" "$leading_zero_manifest"
cat >> "$leading_zero_manifest" <<'LEADING_ZERO'
NODOS=(
  "node-a:192.0.2.010:eth0:150:ssh_key_node_a"
  "node-b:192.0.2.11:eth0:100:ssh_key_node_b"
)
LEADING_ZERO
if FIP_MANIFIESTO="$leading_zero_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una IPv4 de gestión con octeto ambiguo' >&2
  exit 1
fi
grep -Fq 'IP de gestión no válida en node-a' "$output"

duplicate_management_manifest="$test_root/manifiesto-ip-gestion-duplicada.sh"
cp "$manifest" "$duplicate_management_manifest"
cat >> "$duplicate_management_manifest" <<'DUPLICATE_MANAGEMENT'
NODOS=(
  "node-a:192.0.2.10:eth0:150:ssh_key_node_a"
  "node-b:192.0.2.10:eth0:100:ssh_key_node_b"
)
DUPLICATE_MANAGEMENT
if FIP_MANIFIESTO="$duplicate_management_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una IP de gestión repetida' >&2
  exit 1
fi
grep -Fq 'IP de gestión repetida: 192.0.2.10' "$output"

vip_management_manifest="$test_root/manifiesto-vip-gestion.sh"
cp "$manifest" "$vip_management_manifest"
cat >> "$vip_management_manifest" <<'VIP_MANAGEMENT'
DIRECCIONES=("service-a:192.0.2.10:51:8080:/health:-")
VIP_MANAGEMENT
if FIP_MANIFIESTO="$vip_management_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una VIP igual a una IP de gestión' >&2
  exit 1
fi
grep -Fq 'coincide con la IP de gestión de un nodo' "$output"

too_many_nodes_manifest="$test_root/manifiesto-demasiados-nodos.sh"
{
  printf '%s\n' 'DHCP_DESDE=200' 'VIP_PREFIJO=24' 'NODOS=('
  for indice in $(seq 0 16); do
    printf '  "node-%02d:192.0.2.%d:eth0:%d:ssh_key_node_a"\n' \
      "$indice" "$((10 + indice))" "$((200 - indice))"
  done
  printf '%s\n' ')' 'DIRECCIONES=("service-a:192.0.2.100:51:8080:/health:-")'
} > "$too_many_nodes_manifest"
if FIP_MANIFIESTO="$too_many_nodes_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptaron más de 16 nodos' >&2
  exit 1
fi
grep -Fq 'admite como máximo 16 nodos' "$output"

for invalid_delay in texto 08 1001; do
  invalid_delay_manifest="$test_root/manifiesto-retardo-$invalid_delay.sh"
  cp "$manifest" "$invalid_delay_manifest"
  printf '\nPREEMPT_DELAY=%q\n' "$invalid_delay" >> "$invalid_delay_manifest"
  if FIP_MANIFIESTO="$invalid_delay_manifest" FIP_SECRETS_DIR="$secrets_dir" \
      bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
    echo "Se aceptó PREEMPT_DELAY no canónico o fuera de rango: $invalid_delay" >&2
    exit 1
  fi
  grep -Fq 'PREEMPT_DELAY debe ser un entero decimal entre 0 y 1000' "$output"
done

custom_delay_manifest="$test_root/manifiesto-retardo-90.sh"
cp "$manifest" "$custom_delay_manifest"
printf '\nPREEMPT_DELAY=90\n' >> "$custom_delay_manifest"
FIP_MANIFIESTO="$custom_delay_manifest" FIP_SECRETS_DIR="$secrets_dir" \
  bash "$repo_root/deploy-floating-ip.sh" --dry-run > "$output"
grep -Eq 'preempt_delay[[:space:]]+90' "$output"

priority_manifest="$test_root/manifiesto-prioridades-desordenadas.sh"
cp "$manifest" "$priority_manifest"
cat >> "$priority_manifest" <<'PRIORITIES'
NODOS=(
  "node-a:192.0.2.10:eth0:100:ssh_key_node_a"
  "node-b:192.0.2.11:eth0:150:ssh_key_node_b"
)
PRIORITIES
FIP_MANIFIESTO="$priority_manifest" FIP_SECRETS_DIR="$secrets_dir" \
  bash "$repo_root/deploy-floating-ip.sh" --dry-run > "$output"
python3 - "$output" <<'PY'
import re
import sys

texto = open(sys.argv[1], encoding="utf-8").read()
seccion = texto.split("node-a (orden base", 1)[1].split("node-b (orden base", 1)[0]
bloque = re.search(
    r"vrrp_instance SERVICE_A \{(?:(?!vrrp_instance).)*?priority\s+150(?:\s|$)",
    seccion,
    re.S,
)
assert bloque, seccion
PY

if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    FIP_DATA_DIR=/mnt/user/appdata/floating-ip \
    FIP_REMOTE_SECRETS_DIR=/mnt/user/appdata/floating-ip/secrets \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >/dev/null 2>&1; then
  echo 'Se aceptaron secretos anidados dentro de FIP_DATA_DIR' >&2
  exit 1
fi

dry_existing="$test_root/dry-data-existente"
mkdir -p "$dry_existing"
printf '%s\n' 'no-cambiar-en-dry-run' > "$dry_existing/pool.json"
chmod 0755 "$dry_existing"
chmod 0644 "$dry_existing/pool.json"
dry_checksum="$(sha256sum "$dry_existing/pool.json")"
FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
  FIP_DATA_DIR="$dry_existing" \
  bash "$repo_root/deploy-floating-ip.sh" --dry-run >/dev/null
test "$(stat -c %a "$dry_existing")" = "755"
test "$(stat -c %a "$dry_existing/pool.json")" = "644"
test "$dry_checksum" = "$(sha256sum "$dry_existing/pool.json")"

long_route_manifest="$test_root/manifiesto-ruta-larga.sh"
long_entry_manifest="$test_root/manifiesto-entrada-larga.sh"
long_route="/$(printf '%0256d' 0 | tr '0' a)"
long_preferred="$(printf '%0600d' 0 | tr '0' a)"
cp "$manifest" "$long_route_manifest"
printf '\nDIRECCIONES=("service-a:192.0.2.100:51:8080:%s:-")\n' \
  "$long_route" >> "$long_route_manifest"
if FIP_MANIFIESTO="$long_route_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una ruta de chequeo mayor de 256 caracteres' >&2
  exit 1
fi
grep -Fq 'ruta de salud de service-a supera 256 caracteres' "$output"

cp "$manifest" "$long_entry_manifest"
printf '\nDIRECCIONES=("service-a:192.0.2.100:51:8080:/health:%s")\n' \
  "$long_preferred" >> "$long_entry_manifest"
if FIP_MANIFIESTO="$long_entry_manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >"$output" 2>&1; then
  echo 'Se aceptó una entrada de DIRECCIONES mayor de 512 caracteres' >&2
  exit 1
fi
grep -Fq 'entrada de DIRECCIONES supera el máximo de 512 caracteres' "$output"

printf '%s\n%s\n' \
  'ssssssssssssssssssssssssssssssssssssssss' \
  'segunda-linea-no-admitida' \
  > "$secrets_dir/keepalived-session-secret.txt"
if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
    bash "$repo_root/deploy-floating-ip.sh" --dry-run >/dev/null 2>&1; then
  echo 'Se aceptó un fichero de secreto con más de una línea' >&2
  exit 1
fi

printf '%s\n' 'ssssssssssssssssssssssssssssssssssssssss' \
  > "$secrets_dir/keepalived-session-secret.txt"
invalid_data_dirs=(
  "ruta-relativa"
  "/boot/config/floating-ip"
  "$test_root/./no-normalizado"
  "$test_root/sub/../no-normalizado"
)
for invalid_data_dir in "${invalid_data_dirs[@]}"; do
  if FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$secrets_dir" \
      FIP_DATA_DIR="$invalid_data_dir" \
      FIP_REMOTE_SECRETS_DIR=/mnt/user/appdata/floating-ip/secrets \
      bash "$repo_root/deploy-floating-ip.sh" --dry-run >/dev/null 2>&1; then
    echo 'Se ha aceptado un FIP_DATA_DIR inseguro' >&2
    exit 1
  fi
done

printf 'deploy dry-run security tests: OK\n'
