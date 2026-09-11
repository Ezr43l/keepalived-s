#!/usr/bin/env bash
# Prepara los bind mounts de Compose para el runtime sin DAC_OVERRIDE ni CHOWN.
set -euo pipefail
umask 077

uso() {
  cat >&2 <<'EOF'
Uso:
  sudo ./prepare-compose-storage.sh [--fresh-install] DATA_DIR SECRETS_DIR

SECRETS_DIR debe ser una carpeta dedicada que contenga únicamente:
  keepalived-vrrp.txt
  keepalived-session-secret.txt
  keepalived-cluster-token.txt

El script conserva el contenido, rechaza enlaces y hardlinks, y deja ambos
árboles accesibles exclusivamente por root. --fresh-install autoriza una sola
inicialización vacía y sólo se acepta si DATA_DIR está completamente vacío.
EOF
  exit 2
}

FRESH_INSTALL=""
if [[ "${1:-}" == "--fresh-install" ]]; then
  FRESH_INSTALL=1
  shift
fi
[[ $# -eq 2 ]] || uso
[[ "$(id -u)" -eq 0 ]] || {
  echo "Debe ejecutarse como root (por ejemplo, mediante sudo)." >&2
  exit 2
}
for utilidad in readlink stat chown chmod mkdir find mktemp ln sync rm; do
  command -v "$utilidad" >/dev/null 2>&1 || {
    echo "Falta la utilidad requerida: $utilidad" >&2
    exit 2
  }
done

normalizar_sin_enlaces() { # <ruta>
  local entrada="$1" ruta componente salida=""
  local -a componentes=()
  while [[ "$entrada" == ./* ]]; do entrada="${entrada#./}"; done
  [[ -n "$entrada" && "$entrada" != *//* && "$entrada" != *$'\n'* \
      && "$entrada" != *$'\r'* ]] || {
    echo "Ruta no permitida: $1" >&2
    return 1
  }
  if [[ "$entrada" == /* ]]; then
    ruta="$entrada"
  else
    ruta="$(pwd -P)/$entrada"
  fi
  while [[ "$ruta" != "/" && "$ruta" == */ ]]; do ruta="${ruta%/}"; done
  IFS='/' read -r -a componentes <<< "${ruta#/}"
  for componente in "${componentes[@]}"; do
    [[ -n "$componente" && "$componente" != "." && "$componente" != ".." ]] || {
      echo "La ruta debe estar normalizada, sin componentes . o ..: $1" >&2
      return 1
    }
    salida="$salida/$componente"
  done
  [[ -n "$salida" && "$salida" != "/" ]] || {
    echo "Ruta no permitida: $1" >&2
    return 1
  }
  printf '%s\n' "$salida"
}

comprobar_componentes_directorio() { # <ruta-absoluta>
  local ruta="$1" actual="" componente
  local -a componentes=()
  IFS='/' read -r -a componentes <<< "${ruta#/}"
  for componente in "${componentes[@]}"; do
    actual="$actual/$componente"
    [[ ! -L "$actual" ]] || {
      echo "La ruta no puede atravesar enlaces simbólicos: $ruta" >&2
      return 1
    }
    [[ ! -e "$actual" || -d "$actual" ]] || {
      echo "Un componente de la ruta no es un directorio: $actual" >&2
      return 1
    }
  done
}

crear_marcadores_fresh() ( # <data-dir-root-only>
  local directorio="$1" nombre temporal=""
  local -a creados=()
  # shellcheck disable=SC2329  # invocada indirectamente por trap(1)
  limpiar_incompletos() {
    [[ -z "$temporal" ]] || rm -f -- "$temporal"
    for nombre in "${creados[@]}"; do rm -f -- "$nombre"; done
  }
  trap limpiar_incompletos EXIT
  trap 'exit 1' HUP INT TERM
  for nombre in .bootstrap-pool .bootstrap-security; do
    [[ ! -e "$directorio/$nombre" && ! -L "$directorio/$nombre" ]]
    temporal="$(mktemp "$directorio/.bootstrap.XXXXXX")"
    printf '%s\n' 'fresh-install-v1' > "$temporal"
    chown 0:0 -- "$temporal"
    chmod 0600 -- "$temporal"
    ln -- "$temporal" "$directorio/$nombre"
    rm -f -- "$temporal"
    temporal=""
    creados+=("$directorio/$nombre")
  done
  sync -f "$directorio" 2>/dev/null || sync
  creados=()
  trap - EXIT HUP INT TERM
)

DATA_DIR="$(normalizar_sin_enlaces "$1")"
SECRETS_DIR="$(normalizar_sin_enlaces "$2")"
NOMBRES_SECRETOS=(
  keepalived-vrrp.txt
  keepalived-session-secret.txt
  keepalived-cluster-token.txt
)
SECRETOS=()
for nombre in "${NOMBRES_SECRETOS[@]}"; do
  SECRETOS+=("$SECRETS_DIR/$nombre")
done

[[ "$DATA_DIR" != "/boot" && "$DATA_DIR" != /boot/* ]] || {
  echo "DATA_DIR no puede estar bajo /boot." >&2
  exit 2
}

[[ "$SECRETS_DIR" != "/boot" && "$SECRETS_DIR" != /boot/* ]] || {
  echo "SECRETS_DIR no puede estar bajo /boot." >&2
  exit 2
}
[[ "$SECRETS_DIR" != "$DATA_DIR" && "$SECRETS_DIR" != "$DATA_DIR/"* \
    && "$DATA_DIR" != "$SECRETS_DIR/"* ]] || {
  echo "Los secretos y DATA_DIR deben pertenecer a árboles separados." >&2
  exit 2
}

comprobar_componentes_directorio "$DATA_DIR"
comprobar_componentes_directorio "$SECRETS_DIR"

[[ -d "$SECRETS_DIR" && ! -L "$SECRETS_DIR" \
    && "$(readlink -f -- "$SECRETS_DIR")" == "$SECRETS_DIR" ]] || {
  echo "SECRETS_DIR debe existir y no puede atravesar enlaces simbólicos." >&2
  exit 2
}

# El directorio se va a convertir en root-only: para limitar estrictamente el
# alcance, debe ser dedicado y no puede contener ningún cuarto objeto.
for entrada in "$SECRETS_DIR"/* "$SECRETS_DIR"/.[!.]* "$SECRETS_DIR"/..?*; do
  [[ -e "$entrada" || -L "$entrada" ]] || continue
  permitido=""
  for nombre in "${NOMBRES_SECRETOS[@]}"; do
    [[ "$entrada" == "$SECRETS_DIR/$nombre" ]] && permitido=1
  done
  [[ -n "$permitido" ]] || {
    echo "SECRETS_DIR no es una carpeta dedicada; objeto inesperado: $entrada" >&2
    exit 2
  }
done

# Primero se audita todo; si algo es inseguro no se cambian propietarios ni
# permisos parcialmente.
for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
    .cluster-protocol-v2; do
  ruta="$DATA_DIR/$nombre"
  if [[ -e "$ruta" || -L "$ruta" ]]; then
    [[ -f "$ruta" && ! -L "$ruta" \
        && "$(readlink -f -- "$ruta")" == "$ruta" \
        && "$(stat -c %h -- "$ruta")" == "1" ]] || {
      echo "$ruta debe ser un fichero regular sin enlaces ni hardlinks." >&2
      exit 2
    }
  fi
done

if [[ -z "$FRESH_INSTALL" ]]; then
  for marcador in .bootstrap-pool .bootstrap-security .deploy-freeze; do
    [[ ! -e "$DATA_DIR/$marcador" && ! -L "$DATA_DIR/$marcador" ]] || {
      echo "$DATA_DIR/$marcador es un marcador transaccional residual; no se puede preparar como actualización." >&2
      exit 2
    }
  done
fi

VALORES_SECRETOS=()
for secreto in "${SECRETOS[@]}"; do
  [[ -f "$secreto" && ! -L "$secreto" \
      && "$(readlink -f -- "$secreto")" == "$secreto" \
      && "$(stat -c %h -- "$secreto")" == "1" \
      && "$(stat -c %s -- "$secreto")" -le 4096 ]] || {
    echo "$secreto debe existir y ser un fichero regular sin enlaces ni hardlinks." >&2
      exit 2
  }
  mapfile -t lineas_secreto < "$secreto"
  (( ${#lineas_secreto[@]} == 1 )) \
    && [[ "${lineas_secreto[0]}" != *$'\r'* ]] || {
    echo "$secreto debe contener exactamente una línea sin retornos de carro." >&2
    exit 2
  }
  VALORES_SECRETOS+=("${lineas_secreto[0]}")
done
[[ "${VALORES_SECRETOS[0]}" =~ ^[A-Za-z0-9._-]{1,8}$ ]] || {
  echo "La clave VRRP debe tener entre 1 y 8 caracteres seguros." >&2
  exit 2
}
for indice in 1 2; do
  [[ "${VALORES_SECRETOS[$indice]}" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || {
    echo "Los secretos de sesión y clúster deben ser base64url de 32-128 caracteres." >&2
    exit 2
  }
done
[[ "${VALORES_SECRETOS[1]}" != "${VALORES_SECRETOS[2]}" ]] || {
  echo "Los secretos de sesión y clúster deben ser distintos." >&2
  exit 2
}

mkdir -p -- "$DATA_DIR"
[[ ! -L "$DATA_DIR" && "$(readlink -f -- "$DATA_DIR")" == "$DATA_DIR" ]] || {
  echo "DATA_DIR no puede atravesar enlaces simbólicos." >&2
  exit 2
}

if [[ -n "$FRESH_INSTALL" ]]; then
  primer_objeto="$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)"
  [[ -z "$primer_objeto" ]] || {
    echo "--fresh-install exige un DATA_DIR completamente vacío." >&2
    exit 2
  }
fi

chown 0:0 -- "$DATA_DIR"
chmod 0700 -- "$DATA_DIR"
for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
    .cluster-protocol-v2; do
  ruta="$DATA_DIR/$nombre"
  if [[ -e "$ruta" ]]; then
    chown 0:0 -- "$ruta"
    chmod 0600 -- "$ruta"
  fi
done

chown 0:0 -- "$SECRETS_DIR"
chmod 0700 -- "$SECRETS_DIR"
for secreto in "${SECRETOS[@]}"; do
  chown 0:0 -- "$secreto"
  chmod 0400 -- "$secreto"
done

if [[ -n "$FRESH_INSTALL" ]]; then
  crear_marcadores_fresh "$DATA_DIR"
  for marcador in .bootstrap-pool .bootstrap-security; do
    [[ "$(stat -c '%u:%g:%a:%h' -- "$DATA_DIR/$marcador")" == "0:0:600:1" ]]
  done
fi

[[ "$(stat -c '%u:%g:%a' -- "$DATA_DIR")" == "0:0:700" ]]
[[ "$(stat -c '%u:%g:%a' -- "$SECRETS_DIR")" == "0:0:700" ]]
for secreto in "${SECRETOS[@]}"; do
  [[ "$(stat -c '%u:%g:%a:%h' -- "$secreto")" == "0:0:400:1" ]]
done
printf '%s\n' "Almacenamiento Compose preparado sin modificar el contenido."
