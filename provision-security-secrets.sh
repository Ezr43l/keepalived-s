#!/usr/bin/env bash
# Genera, una sola vez, los secretos compartidos de acceso y clúster.
set -euo pipefail
umask 077

DESTINO="${1:-${FIP_SECRETS_DIR:-}}"
[[ -n "$DESTINO" ]] || {
  echo "Uso: $0 /ruta/a/la/carpeta-de-secretos" >&2
  exit 2
}
command -v openssl >/dev/null 2>&1 || {
  echo "Se necesita openssl para usar el generador." >&2
  exit 2
}
for utilidad in stat readlink mktemp ln rm chmod sync; do
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
      && "$entrada" != *$'\r'* ]] || return 1
  [[ "$entrada" == /* ]] && ruta="$entrada" || ruta="$(pwd -P)/$entrada"
  while [[ "$ruta" != "/" && "$ruta" == */ ]]; do ruta="${ruta%/}"; done
  IFS='/' read -r -a componentes <<< "${ruta#/}"
  for componente in "${componentes[@]}"; do
    [[ -n "$componente" && "$componente" != "." && "$componente" != ".." ]] \
      || return 1
    salida="$salida/$componente"
  done
  [[ -n "$salida" && "$salida" != "/" ]] || return 1
  printf '%s\n' "$salida"
}

DESTINO="$(normalizar_sin_enlaces "$DESTINO")" || {
  echo "La ruta de secretos no es segura ni está normalizada." >&2
  exit 2
}
actual=""
IFS='/' read -r -a componentes_destino <<< "${DESTINO#/}"
for componente in "${componentes_destino[@]}"; do
  actual="$actual/$componente"
  [[ ! -L "$actual" ]] || {
    echo "El directorio de secretos no puede atravesar enlaces simbólicos." >&2
    exit 2
  }
  [[ ! -e "$actual" || -d "$actual" ]] || {
    echo "Un componente de la ruta de secretos no es un directorio." >&2
    exit 2
  }
done

destino_existia=""
[[ ! -d "$DESTINO" ]] || destino_existia=1
mkdir -p -- "$DESTINO"
[[ ! -L "$DESTINO" && "$(readlink -f -- "$DESTINO")" == "$DESTINO" ]] || {
  echo "El directorio de secretos no puede ser un enlace simbólico: $DESTINO" >&2
  exit 2
}
if [[ -n "$destino_existia" ]]; then
  modo_destino="$(stat -c %a -- "$DESTINO")"
  [[ "$modo_destino" == "700" \
      && "$(stat -c %u -- "$DESTINO")" == "$(id -u)" ]] || {
    echo "El directorio existente debe pertenecer al usuario actual y tener modo 0700: $DESTINO" >&2
    exit 2
  }
else
  chmod 0700 -- "$DESTINO"
fi

conservar_existente() { # <fichero> <rol>
  local fichero="$1" rol="$2" valor
  if [[ -e "$fichero" || -L "$fichero" ]]; then
    [[ -f "$fichero" && ! -L "$fichero" \
        && "$(readlink -f -- "$fichero")" == "$fichero" \
        && "$(stat -c %h -- "$fichero")" == "1" \
        && "$(stat -c %u -- "$fichero")" == "$(id -u)" \
        && "$(stat -c %s -- "$fichero")" -le 4096 ]] || {
      echo "El destino existente no es un fichero regular seguro: $fichero" >&2
      exit 2
    }
    mapfile -t lineas < "$fichero"
    (( ${#lineas[@]} == 1 )) && [[ "${lineas[0]}" != *$'\r'* ]] || {
      echo "El secreto existente debe contener exactamente una línea: $fichero" >&2
      exit 2
    }
    valor="${lineas[0]}"
    case "$rol" in
      vrrp) [[ "$valor" =~ ^[A-Za-z0-9._-]{1,8}$ ]] ;;
      largo) [[ "$valor" =~ ^[A-Za-z0-9_-]{32,128}$ ]] ;;
      *) return 2 ;;
    esac || {
      echo "El contenido del secreto existente no cumple su contrato: $fichero" >&2
      exit 2
    }
    chmod 600 "$fichero"
    echo "· conservado: $fichero"
    return 0
  fi
  return 1
}

crear_atomico() { # <fichero> <valor>
  local fichero="$1" valor="$2" temporal=""
  temporal="$(mktemp "$DESTINO/.secret.XXXXXX")"
  limpiar_temporal() { [[ -z "$temporal" ]] || rm -f -- "$temporal"; }
  trap limpiar_temporal EXIT
  trap 'exit 1' HUP INT TERM
  printf '%s\n' "$valor" > "$temporal"
  chmod 0600 -- "$temporal"
  if ! ln -- "$temporal" "$fichero"; then
    echo "El destino apareció durante la creación: $fichero" >&2
    exit 2
  fi
  rm -f -- "$temporal"
  temporal=""
  sync -f "$DESTINO" 2>/dev/null || sync
  trap - EXIT HUP INT TERM
}

crear() { # <fichero>
  local fichero="$1"
  conservar_existente "$fichero" largo && return
  crear_atomico "$fichero" "$(openssl rand -hex 32)"
  echo "· creado: $fichero"
}

crear_vrrp() { # <fichero>
  local fichero="$1" valor
  conservar_existente "$fichero" vrrp && return
  # Keepalived limita auth_pass a ocho caracteres. Se usan seis bytes aleatorios
  # codificados como ocho caracteres base64url (48 bits, sin espacios ni padding).
  valor="$(openssl rand -base64 6 | tr '+/' '-_')"
  [[ "$valor" =~ ^[A-Za-z0-9_-]{8}$ ]] || {
    echo "No se pudo generar una clave VRRP base64url válida." >&2
    exit 2
  }
  crear_atomico "$fichero" "$valor"
  echo "· creado: $fichero"
}

crear_vrrp "$DESTINO/keepalived-vrrp.txt"
crear "$DESTINO/keepalived-session-secret.txt"
crear "$DESTINO/keepalived-cluster-token.txt"
session="$(<"$DESTINO/keepalived-session-secret.txt")"
cluster="$(<"$DESTINO/keepalived-cluster-token.txt")"
[[ "$session" != "$cluster" ]] || {
  echo "Los secretos de sesión y clúster existentes no pueden ser iguales." >&2
  exit 2
}
unset session cluster
echo "Los valores no se muestran. Conserva esta carpeta fuera del repositorio."
