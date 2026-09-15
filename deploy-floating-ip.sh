#!/usr/bin/env bash
# deploy-floating-ip.sh — direcciones IP que saltan al nodo que sirve de verdad.
#
# Uso:  ./deploy-floating-ip.sh [--dry-run] [--fresh-install] [nodo ...]
#
# Esta versión despliega siempre el clúster completo como una transacción
# N/N. Los nombres de nodo sólo permiten acotar la salida de --dry-run; una
# ejecución real parcial se rechaza antes de abrir ninguna conexión SSH.
#
# Lee el reparto del fichero indicado por FIP_MANIFIESTO mediante manifiesto.sh,
# genera la configuracion VRRP de cada nodo y
# levanta un contenedor «Keepalived» que sostiene las direcciones y sirve el
# panel del reparto.
#
# Como funciona: todos los nodos hablan VRRP entre ellos. El de mayor prioridad
# que este sano sostiene la direccion; si deja de estarlo, otro la reclama en
# segundos. «Sano» no es «la maquina responde» sino «este servicio responde
# AQUI»: el chequeo consulta la URL declarada contra 127.0.0.1, asi que un
# servidor encendido con el servicio caido cede la direccion en vez de
# quedarsela y no servir nada.
set -euo pipefail

# Esta función se envía sin cambios al shell remoto antes de detener o recrear
# contenedores. Sólo prepara metadatos: nunca trunca ni sustituye datos.
# shellcheck disable=SC2329  # invocada en el shell remoto mediante declare -f
preparar_almacen_persistente() ( # <directorio> [<tx-root> <txid> <plantilla>]
  local directorio="$1" tx_root="${2:-}" txid="${3:-}" plantilla="${4:-}"
  local componente actual="" nombre ruta
  local -a componentes=()

  [[ "$directorio" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ ]] || {
    echo "FIP_DATA_DIR debe ser una ruta absoluta segura" >&2
    return 1
  }
  [[ "$directorio" != *"/../"* && "$directorio" != *"/.." \
      && "$directorio" != *"/./"* && "$directorio" != *"/." ]] || {
    echo "FIP_DATA_DIR debe estar normalizado, sin componentes . o .." >&2
    return 1
  }
  [[ "$directorio" != "/boot" && "$directorio" != /boot/* ]] || {
    echo "FIP_DATA_DIR no puede estar bajo /boot" >&2
    return 1
  }
  umask 077

  # Se comprueba cada componente existente antes de mkdir. Comprobar sólo el
  # último permitiría que un padre simbólico desviase la escritura.
  IFS='/' read -r -a componentes <<< "${directorio#/}"
  for componente in "${componentes[@]}"; do
    actual="$actual/$componente"
    [[ ! -L "$actual" ]] || {
      echo "FIP_DATA_DIR no puede atravesar enlaces simbólicos" >&2
      return 1
    }
    if [[ -e "$actual" && ! -d "$actual" ]]; then
      echo "Un componente de FIP_DATA_DIR no es un directorio" >&2
      return 1
    fi
  done

  mkdir -p -- "$directorio"
  [[ -d "$directorio" && ! -L "$directorio" ]] || {
    echo "FIP_DATA_DIR no es un directorio real" >&2
    return 1
  }
  [[ "$(readlink -f -- "$directorio")" == "$directorio" ]] || {
    echo "FIP_DATA_DIR no puede resolverse mediante enlaces simbólicos" >&2
    return 1
  }
  # Primero se auditan todos los objetos. Si uno es inseguro no se cambia el
  # modo de ninguno de los demás y resulta evidente qué debe corregirse.
  for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
      .cluster-protocol-v2; do
    ruta="$directorio/$nombre"
    [[ ! -L "$ruta" ]] || {
      echo "$nombre no puede ser un enlace simbólico" >&2
      return 1
    }
    if [[ -e "$ruta" ]]; then
      [[ -f "$ruta" && "$(readlink -f -- "$ruta")" == "$ruta" \
          && "$(stat -c %h -- "$ruta")" == "1" ]] || {
        echo "$nombre debe ser un fichero regular sin hardlinks" >&2
        return 1
      }
    fi
  done
  for nombre in .bootstrap-pool .bootstrap-security; do
    ruta="$directorio/$nombre"
    [[ ! -e "$ruta" && ! -L "$ruta" ]] || {
      echo "$nombre es un marcador transaccional residual que debe recuperarse" >&2
      return 1
    }
  done
  ruta="$directorio/.deploy-freeze"
  if [[ -e "$ruta" || -L "$ruta" ]]; then
    [[ -n "$tx_root" && -n "$txid" && -n "$plantilla" \
        && "$(type -t fip_tx_install_freeze)" == function ]] || {
      echo ".deploy-freeze es un marcador transaccional residual que debe recuperarse" >&2
      return 1
    }
    # La libreria comprueba journal/TXID, inode, hash, propietario, modo y bytes
    # exactos. Reconocer solo el texto del marker no acreditaria su pertenencia.
    fip_tx_install_freeze "$tx_root" "$txid" "$directorio" "$plantilla" \
      || return 1
  fi

  chown 0:0 -- "$directorio"
  chmod 0700 -- "$directorio"
  [[ "$(stat -c '%u:%g:%a' -- "$directorio")" == "0:0:700" ]] || {
    echo "FIP_DATA_DIR debe quedar como root:root 0700" >&2
    return 1
  }

  for nombre in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
      .cluster-protocol-v2; do
    ruta="$directorio/$nombre"
    [[ ! -L "$ruta" ]] || {
      echo "$nombre cambió a enlace simbólico durante la preparación" >&2
      return 1
    }
    if [[ -e "$ruta" ]]; then
      [[ -f "$ruta" && "$(readlink -f -- "$ruta")" == "$ruta" \
          && "$(stat -c %h -- "$ruta")" == "1" ]] || {
        echo "$nombre cambió y ya no es un fichero regular sin hardlinks" >&2
        return 1
      }
      chown 0:0 -- "$ruta"
      chmod 0600 -- "$ruta"
      [[ "$(stat -c '%u:%g:%a' -- "$ruta")" == "0:0:600" ]] || {
        echo "$nombre debe quedar como root:root 0600" >&2
        return 1
      }
    fi
  done
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
auditar_control_remoto() ( # <data-dir> <contenedor> <sha-marker> <protocolo>
  local directorio="$1" contenedor="$2" huella_esperada="$3" protocolo="$4"
  local marcador ruta huella
  local -a montajes=()
  set -euo pipefail
  [[ "$huella_esperada" =~ ^[0-9a-f]{64}$ \
      && "$protocolo" =~ ^(absent|legacy|v2)$ ]] || return 1

  if docker inspect "$contenedor" >/dev/null 2>&1; then
    mapfile -t montajes < <(
      docker inspect --format \
        '{{range .Mounts}}{{if eq .Destination "/datos"}}{{println .Source}}{{end}}{{end}}' \
        "$contenedor"
    )
    (( ${#montajes[@]} == 1 )) && [[ "${montajes[0]}" == "$directorio" ]] || {
      echo "el montaje /datos activo no coincide con FIP_DATA_DIR" >&2
      return 1
    }
  fi

  if [[ ! -e "$directorio" && ! -L "$directorio" ]]; then
    printf '%s\n' marker=absent
    return 0
  fi
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" ]] || {
    echo "FIP_DATA_DIR remoto no es un directorio real normalizado" >&2
    return 1
  }
  for marcador in .bootstrap-pool .bootstrap-security .deploy-freeze; do
    ruta="$directorio/$marcador"
    [[ ! -e "$ruta" && ! -L "$ruta" ]] || {
      echo "$marcador residual exige recuperar la operación anterior antes de desplegar" >&2
      return 1
    }
  done

  ruta="$directorio/.cluster-protocol-v2"
  if [[ ! -e "$ruta" && ! -L "$ruta" ]]; then
    printf '%s\n' marker=absent
    return 0
  fi
  [[ -f "$ruta" && ! -L "$ruta" \
      && "$(readlink -f -- "$ruta")" == "$ruta" \
      && "$(stat -c %h -- "$ruta")" == 1 \
      && "$(stat -c '%u:%g:%a' -- "$ruta")" == 0:0:600 \
      && "$(stat -c %s -- "$ruta")" -le 4096 ]] || {
    echo ".cluster-protocol-v2 no cumple el contrato root-only" >&2
    return 1
  }
  huella="$(sha256sum -- "$ruta")"; huella="${huella%% *}"
  [[ "$huella" == "$huella_esperada" ]] || {
    echo ".cluster-protocol-v2 no corresponde a la topología declarada" >&2
    return 1
  }
  [[ "$protocolo" != legacy ]] || {
    echo "un contenedor legacy no puede reutilizar una capacidad v2 persistida" >&2
    return 1
  }
  printf '%s\n' marker=present
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
auditar_artefacto_actual_remoto() ( # <contenedor> <plantilla> <protocolo> <version>
  local contenedor="$1" plantilla="$2" protocolo="$3" version="$4"
  local imagen_id revision version_real protocolo_real referencia linea encontrada=""
  local -a digests=()
  set -euo pipefail
  [[ "$protocolo" =~ ^(absent|legacy|v2)$ \
      && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] \
    || return 1
  if [[ "$protocolo" == absent ]]; then
    printf '%s\n' artifact=absent
    return 0
  fi
  docker inspect "$contenedor" >/dev/null 2>&1 || return 1
  if [[ "$protocolo" == legacy ]]; then
    printf '%s\n' artifact=legacy
    return 0
  fi

  imagen_id="$(docker inspect --format '{{.Image}}' "$contenedor")"
  [[ "$imagen_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  revision="$(docker image inspect --format \
    '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$imagen_id")"
  version_real="$(docker image inspect --format \
    '{{index .Config.Labels "org.opencontainers.image.version"}}' "$imagen_id")"
  protocolo_real="$(docker image inspect --format \
    '{{index .Config.Labels "io.ezr43l.cluster-protocol"}}' "$imagen_id")"
  [[ "$revision" =~ ^[0-9a-f]{12,64}$ \
      && "$version_real" == "$version" && "$protocolo_real" == v2 ]] || return 1

  [[ -f "$plantilla" && ! -L "$plantilla" \
      && "$(stat -c %s -- "$plantilla")" -le 1048576 ]] || return 1
  referencia="$(sed -n -E \
    's#^[[:space:]]*<Repository>([^<]+)</Repository>[[:space:]]*$#\1#p' \
    "$plantilla" | tail -1)"
  [[ "$referencia" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] \
    || return 1
  mapfile -t digests < <(
    docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
      "$imagen_id"
  )
  for linea in "${digests[@]}"; do
    [[ "$linea" == "$referencia" ]] && encontrada=1
  done
  [[ -n "$encontrada" ]] || return 1
  printf 'artifact=v2;revision=%s;digest=%s;image=%s\n' \
    "$revision" "$referencia" "$imagen_id"
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
observar_estado_remoto() ( # <data-dir> <pool.json|security.json>
  local directorio="$1" nombre="$2" ruta huella bytes
  set -euo pipefail
  [[ "$nombre" == pool.json || "$nombre" == security.json ]] || return 1
  if [[ ! -e "$directorio" && ! -L "$directorio" ]]; then
    printf '%s\n' absent
    return 0
  fi
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" \
      && "$(stat -c '%u:%g:%a' -- "$directorio")" == 0:0:700 ]] || return 1
  ruta="$directorio/$nombre"
  if [[ ! -e "$ruta" && ! -L "$ruta" ]]; then
    printf '%s\n' absent
    return 0
  fi
  [[ -f "$ruta" && ! -L "$ruta" \
      && "$(readlink -f -- "$ruta")" == "$ruta" \
      && "$(stat -c %h -- "$ruta")" == 1 \
      && "$(stat -c '%u:%g:%a' -- "$ruta")" == 0:0:600 ]] || return 1
  bytes="$(stat -c %s -- "$ruta")"
  (( bytes <= 512 * 1024 )) || return 1
  huella="$(sha256sum -- "$ruta")"; huella="${huella%% *}"
  [[ "$huella" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf 'present;%s;%s\n' "$huella" "$bytes"
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH; bytes por stdout
descargar_estado_remoto() ( # <data-dir> <nombre> <sha256> <bytes>
  local directorio="$1" nombre="$2" esperada="$3" bytes_esperados="$4"
  local ruta huella_previa huella_posterior bytes
  set -euo pipefail
  [[ "$nombre" == pool.json || "$nombre" == security.json ]] || return 1
  [[ "$esperada" =~ ^[0-9a-f]{64}$ \
      && "$bytes_esperados" =~ ^[0-9]+$ \
      && "$bytes_esperados" -le $((512 * 1024)) ]] || return 1
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" \
      && "$(stat -c '%u:%g:%a' -- "$directorio")" == 0:0:700 ]] || return 1
  ruta="$directorio/$nombre"
  [[ -f "$ruta" && ! -L "$ruta" \
      && "$(readlink -f -- "$ruta")" == "$ruta" \
      && "$(stat -c %h -- "$ruta")" == 1 \
      && "$(stat -c '%u:%g:%a' -- "$ruta")" == 0:0:600 ]] || return 1
  bytes="$(stat -c %s -- "$ruta")"
  [[ "$bytes" == "$bytes_esperados" ]] || return 1
  huella_previa="$(sha256sum -- "$ruta")"; huella_previa="${huella_previa%% *}"
  [[ "$huella_previa" == "$esperada" ]] || return 1
  cat -- "$ruta"
  bytes="$(stat -c %s -- "$ruta")"
  huella_posterior="$(sha256sum -- "$ruta")"; huella_posterior="${huella_posterior%% *}"
  [[ "$bytes" == "$bytes_esperados" && "$huella_posterior" == "$esperada" ]]
)

# shellcheck disable=SC2329  # invocada en el shell remoto mediante declare -f
escribir_configuracion_atomica() ( # <directorio> <destino>; contenido por stdin
  local directorio="$1" destino="$2" temporal=""
  [[ "$destino" == "$directorio/keepalived.conf" ]] || {
    echo "El destino de configuración no pertenece a FIP_DATA_DIR" >&2
    return 1
  }
  [[ -d "$directorio" && ! -L "$directorio" ]] || {
    echo "FIP_DATA_DIR dejó de ser un directorio real" >&2
    return 1
  }
  [[ "$(readlink -f -- "$directorio")" == "$directorio" ]] || {
    echo "FIP_DATA_DIR atraviesa un enlace simbólico" >&2
    return 1
  }
  [[ "$(stat -c '%u:%g:%a' -- "$directorio")" == "0:0:700" ]] || {
    echo "FIP_DATA_DIR ya no conserva root:root 0700" >&2
    return 1
  }
  if [[ -e "$destino" || -L "$destino" ]]; then
    [[ -f "$destino" && ! -L "$destino" ]] || {
      echo "keepalived.conf debe ser un fichero regular, nunca un enlace" >&2
      return 1
    }
  fi

  umask 077
  temporal="$(mktemp "$directorio/.keepalived.conf.XXXXXX")"
  limpiar_config_temporal() { rm -f -- "$temporal"; }
  trap limpiar_config_temporal EXIT
  trap 'exit 1' HUP INT TERM
  cat > "$temporal"
  [[ -s "$temporal" && -f "$temporal" && ! -L "$temporal" ]] || {
    echo "La configuración generada está vacía o no es regular" >&2
    return 1
  }
  chown 0:0 -- "$temporal"
  chmod 0600 -- "$temporal"
  [[ "$(stat -c '%u:%g:%a' -- "$temporal")" == "0:0:600" ]] || {
    echo "El temporal de configuración no es root:root 0600" >&2
    return 1
  }
  # `sync` es deliberadamente global: está disponible en Unraid sin exigir
  # Python ni utilidades adicionales y hace duraderos contenido y metadatos.
  sync

  # Se vuelve a validar justo antes del rename. El directorio root-only evita
  # cambios de usuarios sin privilegios entre esta comprobación y el mv.
  if [[ -e "$destino" || -L "$destino" ]]; then
    [[ -f "$destino" && ! -L "$destino" ]] || {
      echo "keepalived.conf cambió de tipo durante la instalación" >&2
      return 1
    }
  fi
  mv -f -- "$temporal" "$destino"
  sync
  trap - EXIT HUP INT TERM
  [[ -f "$destino" && ! -L "$destino" ]]
  [[ "$(stat -c '%u:%g:%a' -- "$destino")" == "0:0:600" ]]
)

# Genera un snapshot legacy sin revisión: el primer arranque lo migra mediante
# el contrato de pool.py. La marca se calcula una sola vez por despliegue y las
# entradas se ordenan por IPv4, de modo que todos los nodos reciben exactamente
# los mismos bytes sin publicar una fecha ficticia.
generar_semilla_pool() { # <marca_utc> <dhcp_desde> <entrada DIRECCIONES>...
  python3 - "$@" <<'PY'
import ipaddress
import json
import sys

marca = sys.argv[1]
dhcp_desde = int(sys.argv[2])
direcciones = []
for cruda in sys.argv[3:]:
    partes = cruda.split(":", 5)
    if len(partes) == 5:
        partes.append("")
    servicio, ip, vrid, puerto, ruta, preferente = partes
    puerto = int(puerto)
    direcciones.append({
        "ip": ip,
        "vrid": int(vrid),
        "estado": "en_uso",
        "servicio": servicio,
        "descripcion": "",
        "puertos": [puerto],
        "chequeo": {"puerto": puerto, "ruta": ruta},
        "preferente": None if preferente in ("", "-") else preferente,
        "notas": "",
        "creada": marca,
    })
direcciones.sort(key=lambda entrada: int(ipaddress.IPv4Address(entrada["ip"])))
semilla = {
    "version": 1,
    "actualizado": marca,
    "dhcp_desde": dhcp_desde,
    "mantenimiento": [],
    "direcciones": direcciones,
    "reclamaciones": {},
}
json.dump(semilla, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

# shellcheck disable=SC2329  # invocada en el shell remoto mediante declare -f
instalar_semilla_pool() ( # <directorio> <sha256>; semilla por stdin
  local directorio="$1" esperada="$2" destino temporal="" real bytes
  destino="$directorio/pool.json"
  [[ "$esperada" =~ ^[0-9a-f]{64}$ ]] || {
    echo "La huella de la semilla del pool no es válida" >&2
    return 1
  }
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" ]] || {
    echo "FIP_DATA_DIR dejó de ser un directorio real" >&2
    return 1
  }
  [[ "$(stat -c '%u:%g:%a' -- "$directorio")" == "0:0:700" ]] || {
    echo "FIP_DATA_DIR ya no conserva root:root 0700" >&2
    return 1
  }

  if [[ -e "$destino" || -L "$destino" ]]; then
    [[ -f "$destino" && ! -L "$destino" ]] || {
      echo "pool.json existente no es un fichero regular" >&2
      return 1
    }
    [[ "$(stat -c '%u:%g:%a' -- "$destino")" == "0:0:600" ]] || {
      echo "pool.json existente ya no conserva root:root 0600" >&2
      return 1
    }
    # Se consume stdin para que el emisor termine limpiamente, pero el fichero
    # existente no se abre para escritura ni se compara con la semilla.
    cat >/dev/null
    printf '%s\n' 'pool.json existente: preservado'
    return 0
  fi

  umask 077
  temporal="$(mktemp "$directorio/.pool.seed.XXXXXX")"
  limpiar_semilla_temporal() {
    [[ -z "$temporal" ]] || rm -f -- "$temporal"
  }
  trap limpiar_semilla_temporal EXIT
  trap 'exit 1' HUP INT TERM
  cat > "$temporal"
  [[ -s "$temporal" && -f "$temporal" && ! -L "$temporal" ]] || {
    echo "La semilla recibida está vacía o no es regular" >&2
    return 1
  }
  bytes="$(wc -c < "$temporal")"
  (( bytes <= 512 * 1024 )) || {
    echo "La semilla recibida supera el máximo seguro de 512 KiB" >&2
    return 1
  }
  real="$(sha256sum "$temporal")"
  real="${real%% *}"
  [[ "$real" == "$esperada" ]] || {
    echo "La semilla recibida está incompleta o fue alterada" >&2
    return 1
  }
  chown 0:0 -- "$temporal"
  chmod 0600 -- "$temporal"
  [[ "$(stat -c '%u:%g:%a' -- "$temporal")" == "0:0:600" ]] || {
    echo "La semilla temporal no es root:root 0600" >&2
    return 1
  }
  sync -f "$temporal" 2>/dev/null || sync

  # link(2) crea el nombre de destino de forma atómica y falla con EEXIST: a
  # diferencia de mv -f, nunca puede sustituir un pool creado en paralelo.
  if ln -- "$temporal" "$destino" 2>/dev/null; then
    rm -f -- "$temporal"
    temporal=""
    sync -f "$directorio" 2>/dev/null || sync
    [[ -f "$destino" && ! -L "$destino" ]]
    [[ "$(stat -c '%u:%g:%a' -- "$destino")" == "0:0:600" ]]
    real="$(sha256sum "$destino")"
    real="${real%% *}"
    [[ "$real" == "$esperada" ]]
    trap - EXIT HUP INT TERM
    printf '%s\n' 'pool.json inicial creado'
    return 0
  fi

  # Otro proceso pudo crearlo entre la comprobación y link(2). También en ese
  # caso gana siempre el estado ya existente, sin comparar ni sobrescribir.
  if [[ -f "$destino" && ! -L "$destino" \
      && "$(stat -c '%u:%g:%a' -- "$destino")" == "0:0:600" ]]; then
    printf '%s\n' 'pool.json creado en paralelo: preservado'
    return 0
  fi
  echo "No se pudo instalar la semilla del pool de forma atómica" >&2
  return 1
)

# Auditoría exclusivamente de lectura. Compara tanto la ruta de destino nueva
# como el origen que tenga montado un contenedor antiguo, para que cambiar el
# valor predeterminado de carpeta no oculte una credencial todavía activa.
# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
auditar_secretos_remotos() ( # <directorio-destino> <contenedor>
  local directorio="$1" contenedor="$2" rol nombre destino ruta huella encontrados
  local padre
  local especificacion variable_directa variable_fichero linea valor_env destino_env
  local -a especificaciones=(
    "vrrp:vrrp-auth.txt:/run/secrets/fip_vrrp_auth:FIP_VRRP_AUTH_PASS:FIP_VRRP_AUTH_PASS_FILE"
    "session:session-secret.txt:/run/secrets/fip_session_secret:FIP_SESSION_SECRET:FIP_SESSION_SECRET_FILE"
    "cluster:cluster-token.txt:/run/secrets/fip_cluster_token:FIP_CLUSTER_TOKEN:FIP_CLUSTER_TOKEN_FILE"
  )
  local -a montados=() rutas=() entorno=() destinos_contenedor=()
  set -euo pipefail

  for especificacion in "${especificaciones[@]}"; do
    IFS=: read -r rol nombre destino variable_directa variable_fichero \
      <<< "$especificacion"
    rutas=("$directorio/$nombre")
    montados=()
    entorno=()
    destinos_contenedor=("$destino")
    valor_env=""
    if docker inspect "$contenedor" >/dev/null 2>&1; then
      mapfile -t entorno < <(
        docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$contenedor"
      )
      for linea in "${entorno[@]}"; do
        if [[ "$linea" == "$variable_directa="* ]]; then
          [[ -z "$valor_env" ]] || {
            echo "variable directa duplicada: $variable_directa" >&2
            return 1
          }
          valor_env="${linea#*=}"
        elif [[ "$linea" == "$variable_fichero="* ]]; then
          destino_env="${linea#*=}"
          [[ "$destino_env" == /* && "$destino_env" != *$'\n'* \
              && "$destino_env" != *$'\r'* ]] || {
            echo "destino interno de secreto no válido: $rol" >&2
            return 1
          }
          [[ "$destino_env" == "$destino" ]] \
            || destinos_contenedor+=("$destino_env")
        fi
      done
      for destino_env in "${destinos_contenedor[@]}"; do
        montados=()
        mapfile -t montados < <(
          docker inspect --format \
            "{{range .Mounts}}{{if eq .Destination \"$destino_env\"}}{{println .Source}}{{end}}{{end}}" \
            "$contenedor"
        )
        (( ${#montados[@]} <= 1 )) || {
          echo "montaje duplicado para $destino_env" >&2
          return 1
        }
        if (( ${#montados[@]} == 1 )) && [[ -n "${montados[0]}" \
            && "${montados[0]}" != "${rutas[0]}" ]]; then
          rutas+=("${montados[0]}")
        fi
      done
    fi

    encontrados=0
    for ruta in "${rutas[@]}"; do
      [[ "$ruta" == /* && "$ruta" != *$'\n'* && "$ruta" != *$'\r'* ]] || {
        echo "origen de secreto no válido" >&2
        return 1
      }
      if [[ -e "$ruta" || -L "$ruta" ]]; then
        padre="${ruta%/*}"; [[ -n "$padre" ]] || padre=/
        [[ -d "$padre" && ! -L "$padre" \
            && "$(readlink -f -- "$padre")" == "$padre" \
            && "$(stat -c '%u:%g:%a' -- "$padre")" == 0:0:700 ]] || {
          echo "directorio remoto de secreto inseguro: $rol" >&2
          return 1
        }
        [[ -f "$ruta" && ! -L "$ruta" \
            && "$(readlink -f -- "$ruta")" == "$ruta" \
            && "$(stat -c '%u:%g:%a:%h' -- "$ruta")" == "0:0:400:1" \
            && "$(stat -c %s -- "$ruta")" -le 4096 ]] || {
          echo "fichero remoto de secreto inseguro: $rol" >&2
          return 1
        }
        huella="$(sha256sum -- "$ruta")"
        huella="${huella%% *}"
        [[ "$huella" =~ ^[0-9a-f]{64}$ ]] || return 1
        printf '%s=%s\n' "$rol" "$huella"
        (( encontrados += 1 ))
      fi
    done
    if [[ -n "$valor_env" ]]; then
      huella="$(printf '%s\n' "$valor_env" | sha256sum)"
      huella="${huella%% *}"
      printf '%s=%s\n' "$rol" "$huella"
      (( encontrados += 1 ))
    fi
    (( encontrados > 0 )) || printf '%s=missing\n' "$rol"
  done
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
auditar_identidad_remota() ( # <contenedor>
  local contenedor="$1" linea nodo="" tabla="" escritor="" protocolo=""
  local -a entorno=()
  set -euo pipefail
  if ! docker inspect "$contenedor" >/dev/null 2>&1; then
    printf '%s\n' absent
    return 0
  fi
  mapfile -t entorno < <(
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$contenedor"
  )
  for linea in "${entorno[@]}"; do
    [[ "$linea" == FIP_NODO=* ]] && nodo="${linea#*=}"
    [[ "$linea" == FIP_NODOS=* ]] && tabla="${linea#*=}"
  done
  escritor="${tabla%%:*}"
  protocolo="$(docker inspect --format \
    '{{index .Config.Labels "io.ezr43l.cluster-protocol"}}' "$contenedor")"
  [[ "$protocolo" == "v2" ]] || protocolo="legacy"
  [[ "$nodo" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ \
      && "$escritor" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || {
    echo "el contenedor existente no declara una identidad lógica auditable" >&2
    return 1
  }
  printf 'node=%s;writer=%s;protocol=%s\n' "$nodo" "$escritor" "$protocolo"
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
comprobar_alta_fresca_remota() ( # <directorio> <contenedor>
  local directorio="$1" contenedor="$2" primer_objeto=""
  set -euo pipefail
  if docker inspect "$contenedor" >/dev/null 2>&1; then
    echo "ya existe el contenedor $contenedor" >&2
    return 1
  fi
  if [[ -e "$directorio" || -L "$directorio" ]]; then
    [[ -d "$directorio" && ! -L "$directorio" \
        && "$(readlink -f -- "$directorio")" == "$directorio" ]] || {
      echo "FIP_DATA_DIR existente no es un directorio real" >&2
      return 1
    }
    primer_objeto="$(find "$directorio" -mindepth 1 -maxdepth 1 -print -quit)"
    [[ -z "$primer_objeto" ]] || {
      echo "--fresh-install exige FIP_DATA_DIR vacío" >&2
      return 1
    }
  fi
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
instalar_marcadores_bootstrap() ( # <directorio>
  local directorio="$1" nombre temporal=""
  local -a creados=()
  set -euo pipefail
  limpiar_marcadores_incompletos() {
    [[ -z "$temporal" ]] || rm -f -- "$temporal"
    for nombre in "${creados[@]}"; do rm -f -- "$nombre"; done
  }
  trap limpiar_marcadores_incompletos EXIT
  trap 'exit 1' HUP INT TERM
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" \
      && "$(stat -c '%u:%g:%a' -- "$directorio")" == "0:0:700" ]] || {
    echo "FIP_DATA_DIR no conserva el contrato root-only" >&2
    return 1
  }
  umask 077
  for nombre in .bootstrap-pool .bootstrap-security; do
    [[ ! -e "$directorio/$nombre" && ! -L "$directorio/$nombre" ]] || {
      echo "el marcador $nombre ya existe" >&2
      return 1
    }
  done
  for nombre in .bootstrap-pool .bootstrap-security; do
    temporal="$(mktemp "$directorio/.bootstrap.XXXXXX")"
    printf '%s\n' 'fresh-install-v1' > "$temporal"
    chown 0:0 -- "$temporal"
    chmod 0600 -- "$temporal"
    ln -- "$temporal" "$directorio/$nombre"
    rm -f -- "$temporal"
    temporal=""
    creados+=("$directorio/$nombre")
    [[ "$(stat -c '%u:%g:%a:%h' -- "$directorio/$nombre")" \
        == "0:0:600:1" ]]
  done
  sync -f "$directorio" 2>/dev/null || sync
  creados=()
  trap - EXIT HUP INT TERM
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH; valores por stdin
instalar_secretos_remotos() ( # <directorio>
  local directorio="$1" actual="" componente nombre ruta valor esperado real temporal=""
  local -a componentes=()
  local -a nombres_secretos_remotos=(vrrp-auth.txt session-secret.txt cluster-token.txt)
  local -a valores=()
  set -euo pipefail
  umask 077
  limpiar_temporal_secreto() {
    [[ -z "$temporal" ]] || rm -f -- "$temporal"
  }
  trap limpiar_temporal_secreto EXIT
  trap 'exit 1' HUP INT TERM
  [[ "$directorio" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ \
      && "$directorio" != *"/../"* && "$directorio" != *"/.." \
      && "$directorio" != *"/./"* && "$directorio" != *"/." \
      && "$directorio" != "/boot" && "$directorio" != /boot/* ]] || {
    echo "directorio remoto de secretos no válido" >&2
    return 1
  }
  IFS='/' read -r -a componentes <<< "${directorio#/}"
  for componente in "${componentes[@]}"; do
    actual="$actual/$componente"
    [[ ! -L "$actual" ]] || {
      echo "el directorio de secretos no puede atravesar enlaces simbólicos" >&2
      return 1
    }
    [[ ! -e "$actual" || -d "$actual" ]] || {
      echo "un componente del directorio de secretos no es directorio" >&2
      return 1
    }
  done
  mkdir -p -- "$directorio"
  [[ -d "$directorio" && ! -L "$directorio" \
      && "$(readlink -f -- "$directorio")" == "$directorio" ]] || return 1

  IFS= read -r valor; valores+=("$valor")
  IFS= read -r valor; valores+=("$valor")
  IFS= read -r valor; valores+=("$valor")
  if IFS= read -r valor; then
    echo "se recibió contenido adicional para los secretos" >&2
    return 1
  fi
  [[ "${valores[0]}" =~ ^[A-Za-z0-9._-]{1,8}$ \
      && "${valores[1]}" =~ ^[A-Za-z0-9_-]{32,128}$ \
      && "${valores[2]}" =~ ^[A-Za-z0-9_-]{32,128}$ \
      && "${valores[1]}" != "${valores[2]}" ]] || {
    echo "material remoto de secretos no válido" >&2
    return 1
  }

  # Auditar todos antes de cambiar el modo de ninguno.
  for nombre in "${nombres_secretos_remotos[@]}"; do
    ruta="$directorio/$nombre"
    if [[ -e "$ruta" || -L "$ruta" ]]; then
      [[ -f "$ruta" && ! -L "$ruta" \
          && "$(readlink -f -- "$ruta")" == "$ruta" \
          && "$(stat -c %h -- "$ruta")" == "1" \
          && "$(stat -c %s -- "$ruta")" -le 4096 ]] || {
        echo "$nombre no es un fichero de secreto seguro" >&2
        return 1
      }
    fi
  done

  chown 0:0 -- "$directorio"
  chmod 0700 -- "$directorio"
  [[ "$(stat -c '%u:%g:%a' -- "$directorio")" == "0:0:700" ]]

  for indice in "${!nombres_secretos_remotos[@]}"; do
    nombre="${nombres_secretos_remotos[$indice]}"
    valor="${valores[$indice]}"
    ruta="$directorio/$nombre"
    esperado="$(printf '%s\n' "$valor" | sha256sum)"
    esperado="${esperado%% *}"
    if [[ -e "$ruta" || -L "$ruta" ]]; then
      [[ -f "$ruta" && ! -L "$ruta" \
          && "$(readlink -f -- "$ruta")" == "$ruta" \
          && "$(stat -c %h -- "$ruta")" == "1" ]] || return 1
      real="$(sha256sum -- "$ruta")"; real="${real%% *}"
      [[ "$real" == "$esperado" ]] || {
        echo "$nombre cambió después del preflight; se aborta" >&2
        return 1
      }
      chown 0:0 -- "$ruta"
      chmod 0400 -- "$ruta"
      continue
    fi

    temporal="$(mktemp "$directorio/.secret.XXXXXX")"
    printf '%s\n' "$valor" > "$temporal"
    chown 0:0 -- "$temporal"
    chmod 0400 -- "$temporal"
    real="$(sha256sum -- "$temporal")"; real="${real%% *}"
    [[ "$real" == "$esperado" ]]
    if ln -- "$temporal" "$ruta"; then
      rm -f -- "$temporal"
      temporal=""
    else
      rm -f -- "$temporal"
      temporal=""
      echo "$nombre apareció durante la instalación; se aborta" >&2
      return 1
    fi
    [[ "$(stat -c '%u:%g:%a:%h' -- "$ruta")" == "0:0:400:1" ]]
  done
  sync -f "$directorio" 2>/dev/null || sync
  unset valores valor
  trap - EXIT HUP INT TERM
)

# shellcheck disable=SC2329  # se serializa y ejecuta por SSH
extraer_vips_config() ( # <keepalived.conf> <prefijo> <interfaz>
  local configuracion="$1" prefijo="$2" interfaz="$3"
  set -euo pipefail
  [[ "$prefijo" == "24" && "$interfaz" =~ ^[A-Za-z0-9_.:-]+$ ]] || return 1
  if [[ ! -e "$configuracion" && ! -L "$configuracion" ]]; then
    return 0
  fi
  [[ -f "$configuracion" && ! -L "$configuracion" \
      && "$(stat -c %h -- "$configuracion")" == "1" ]] || return 1
  # Coincide únicamente con la línea estructural de virtual_ipaddress. Las IP
  # que aparezcan en comentarios, notas o descripciones nunca son candidatas.
  sed -n -E \
    "s/^[[:space:]]*(([0-9]{1,3}[.]){3}[0-9]{1,3})\/${prefijo}[[:space:]]+dev[[:space:]]+${interfaz}[[:space:]]*$/\\1/p" \
    "$configuracion" | sort -u
)

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

DRY=""
FRESH_INSTALL=""
OBJETIVOS=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --fresh-install) FRESH_INSTALL=1 ;;
    --*) echo "❌ Opción desconocida: $arg" >&2; exit 2 ;;
    *) OBJETIVOS+=("$arg") ;;
  esac
done

# shellcheck source=manifiesto.sh
source ./manifiesto.sh

[[ ${DHCP_DESDE+x} == x && ${NODOS+x} == x && ${DIRECCIONES+x} == x ]] || {
  echo "❌ El manifiesto debe declarar DHCP_DESDE, NODOS y DIRECCIONES." >&2
  echo "   Usa manifiesto.example.sh como punto de partida." >&2
  exit 2
}

# La topologia y las credenciales viven fuera del arbol versionado. El valor
# predeterminado es una carpeta local ignorada por Git, no una ruta del entorno
# donde se desarrolla este proyecto.
SECRETS_DIR="${FIP_SECRETS_DIR:-${SECRETS_DIR:-$REPO_ROOT/.secrets}}"
VRRP_AUTH_FILE_EXPLICIT="${FIP_VRRP_AUTH_FILE:-${VRRP_AUTH_FILE:-}}"
VRRP_AUTH_FILE="${VRRP_AUTH_FILE_EXPLICIT:-$SECRETS_DIR/keepalived-vrrp.txt}"
VRRP_AUTH_PASS="${FIP_VRRP_AUTH_PASS:-}"
if [[ -n "$VRRP_AUTH_PASS" && -n "$VRRP_AUTH_FILE_EXPLICIT" ]]; then
  echo "❌ FIP_VRRP_AUTH_PASS y FIP_VRRP_AUTH_FILE son excluyentes." >&2
  exit 2
fi

# Los tres nodos comparten estos secretos. Se leen desde ficheros fuera del
# repositorio y nunca se imprimen. La primera cuenta se registra en el panel;
# no existe ninguna contraseña inicial de contenedor.
SESSION_SECRET="${FIP_SESSION_SECRET:-}"
CLUSTER_TOKEN="${FIP_CLUSTER_TOKEN:-}"
SESSION_SECRET_FILE_EXPLICIT="${FIP_SESSION_SECRET_FILE:-${SESSION_SECRET_FILE:-}}"
CLUSTER_TOKEN_FILE_EXPLICIT="${FIP_CLUSTER_TOKEN_FILE:-${CLUSTER_TOKEN_FILE:-}}"
if [[ -n "$SESSION_SECRET" && -n "$SESSION_SECRET_FILE_EXPLICIT" ]]; then
  echo "❌ FIP_SESSION_SECRET y FIP_SESSION_SECRET_FILE son excluyentes." >&2
  exit 2
fi
if [[ -n "$CLUSTER_TOKEN" && -n "$CLUSTER_TOKEN_FILE_EXPLICIT" ]]; then
  echo "❌ FIP_CLUSTER_TOKEN y FIP_CLUSTER_TOKEN_FILE son excluyentes." >&2
  exit 2
fi
SESSION_SECRET_FILE="${SESSION_SECRET_FILE_EXPLICIT:-$SECRETS_DIR/keepalived-session-secret.txt}"
CLUSTER_TOKEN_FILE="${CLUSTER_TOKEN_FILE_EXPLICIT:-$SECRETS_DIR/keepalived-cluster-token.txt}"

fichero_privado_local_seguro() { # <ruta>; ejecución Linux del orquestador
  local fichero="$1"
  [[ "$fichero" == /* && -f "$fichero" && ! -L "$fichero" && -r "$fichero" \
      && "$(readlink -f -- "$fichero")" == "$fichero" \
      && "$(stat -c '%u:%a:%h' -- "$fichero")" == "$(id -u):600:1" ]]
}

leer_secreto() { # <variable> <fichero>
  local variable="$1" fichero="$2" valor="${!1:-}"
  local -a lineas=()
  if [[ -z "$valor" ]]; then
    fichero_privado_local_seguro "$fichero" || {
      echo "❌ El fichero local de $variable debe ser propio, canónico, 0600 y sin enlaces: $fichero" >&2
      echo "   Ejecuta provision-security-secrets.sh o define la variable correspondiente." >&2
      exit 2
    }
    [[ "$(wc -c < "$fichero")" -le 4096 ]] || {
      echo "❌ El fichero de $variable supera 4096 bytes: $fichero" >&2
      exit 2
    }
    mapfile -t lineas < "$fichero"
    (( ${#lineas[@]} == 1 )) || {
      echo "❌ El fichero de $variable debe contener exactamente una línea: $fichero" >&2
      exit 2
    }
    valor="${lineas[0]%$'\r'}"
    [[ "$valor" != *$'\r'* ]] || {
      echo "❌ El fichero de $variable contiene retornos de carro no válidos: $fichero" >&2
      exit 2
    }
  fi
  printf -v "$variable" '%s' "$valor"
}

leer_secreto VRRP_AUTH_PASS "$VRRP_AUTH_FILE"
leer_secreto SESSION_SECRET "$SESSION_SECRET_FILE"
leer_secreto CLUSTER_TOKEN "$CLUSTER_TOKEN_FILE"

APP_VERSION="$(tr -d ' \r\n' < VERSION)"
ICONO_URL="https://raw.githubusercontent.com/Ezr43l/keepalived-s/v${APP_VERSION}/logo/icono.png"
IMAGE_REPOSITORY="${FIP_IMAGE_REPOSITORY:-${IMAGE_REPOSITORY:-ghcr.io/ezr43l/keepalived-s}}"
IMAGE_DIGEST="${FIP_IMAGE_DIGEST:-${IMAGE_DIGEST:-}}"
LEGACY_IMAGE_NAME="${FIP_IMAGE_NAME:-${IMAGE_NAME:-keepalived}}"
CONTENEDOR="${FIP_CONTAINER_NAME:-${CONTENEDOR:-Keepalived}}"
DIR_BOOT="${FIP_DATA_DIR:-${FIP_DATOS_DIR:-/mnt/user/appdata/floating-ip}}"
CONF="$DIR_BOOT/keepalived.conf"
# Nunca se guardan bajo DIR_BOOT: ese árbol se monta escribible como /datos y
# permitiría alcanzar por una segunda ruta los secretos montados con :ro.
REMOTE_SECRETS_DIR="${FIP_REMOTE_SECRETS_DIR:-${DIR_BOOT}-secrets}"
PUERTO_POR_OMISION="${FIP_PUERTO:-6060}"
PLANTILLAS="${FIP_TEMPLATE_DIR:-/boot/config/plugins/dockerMan/templates-user}"
PLANTILLA_NOMBRE="${FIP_TEMPLATE_NAME:-my-Keepalived.xml}"
PLANTILLA="$PLANTILLAS/$PLANTILLA_NOMBRE"
VIP_PREFIJO="${FIP_VIP_PREFIX:-${VIP_PREFIX:-24}}"
REGISTROS_POR_NODO="${FIP_REGISTROS_POR_NODO:-${REGISTROS_POR_NODO:-}}"
PREEMPT_DELAY="${PREEMPT_DELAY:-45}"
RENDERER="$REPO_ROOT/render-unraid-template.py"
TX_LIB="$REPO_ROOT/deploy-transaction-lib.sh"
TX_ROOT="${FIP_TRANSACTION_ROOT:-${DIR_BOOT}.deploy-transactions}"
KNOWN_HOSTS_FILE="${FIP_KNOWN_HOSTS_FILE:-$HOME/.ssh/known_hosts}"
SSH_CONNECT_TIMEOUT="${FIP_SSH_CONNECT_TIMEOUT:-10}"
SSH_TOTAL_TIMEOUT="${FIP_SSH_TOTAL_TIMEOUT:-180}"
SSH_CLOCK_SKEW_MAX="${FIP_SSH_CLOCK_SKEW_MAX:-30}"
SSH_CLOCK_RTT_MAX="${FIP_SSH_CLOCK_RTT_MAX:-10}"

# ─────────────────────────────────────────────────────────────────────────────
# Validacion del manifiesto. Antes de tocar nada: un vrid repetido no da error
# en tiempo de ejecucion, da dos servicios peleandose en silencio.
# ─────────────────────────────────────────────────────────────────────────────

# Puertos que los NAVEGADORES se niegan a abrir, aunque esten libres en el
# servidor. Chrome y Firefox mantienen una lista negra de puertos asociados a
# otros protocolos y responden ERR_UNSAFE_PORT sin llegar a conectar. El 6000
# (X11) es un ejemplo habitual: que un puerto esté libre no basta.
PUERTOS_VETADOS="1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 138 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080"
RUTA_RE='^/[A-Za-z0-9._~/%?=&+,-]*$'
MAX_RUTA_CHEQUEO=256
MAX_ENTRADA_DIRECCION=512

ipv4_valida() {
  local ip="$1" octeto
  local -a octetos=()
  IFS=. read -r -a octetos <<< "$ip"
  (( ${#octetos[@]} == 4 )) || return 1
  for octeto in "${octetos[@]}"; do
    [[ "$octeto" =~ ^[0-9]{1,3}$ \
        && ( ${#octeto} -eq 1 || "$octeto" != 0* ) ]] \
      && (( 10#$octeto <= 255 )) || return 1
  done
}

entero_decimal_canonico() { # <valor>
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

rutas_disjuntas() { # <ruta-a> <ruta-b>
  local a="${1%/}" b="${2%/}"
  [[ "$a" != "$b" && "$a" != "$b/"* && "$b" != "$a/"* ]]
}

ipv4_host_unicast_24() {
  local ip="$1" a b _c d
  ipv4_valida "$ip" || return 1
  IFS=. read -r a b _c d <<< "$ip"
  (( 10#$a >= 1 && 10#$a <= 223 && 10#$a != 127 \
      && !(10#$a == 169 && 10#$b == 254) \
      && 10#$d >= 1 && 10#$d <= 254 ))
}

identificador_vrrp() { # <nombre-servicio>
  local identificador="${1^^}"
  printf '%s\n' "${identificador//-/_}"
}

validar() {
  local fallos=0 vrids="" vips="" nombres_vistos=""
  local identificadores_vrrp="" identificador
  local nodos_vistos="" prioridades_vistos=""
  local ips_nodos_vistas=""
  local preferente
  local nombre vip vrid puerto ruta ultimo ip iface prioridad clave
  local par_rutas ruta_a ruta_b
  [[ "$VRRP_AUTH_PASS" =~ ^[A-Za-z0-9._-]{1,8}$ ]] || { echo "❌ La clave VRRP debe tener entre 1 y 8 caracteres seguros." >&2; fallos=1; }
  [[ "$SESSION_SECRET" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || { echo "❌ FIP_SESSION_SECRET debe tener 32-128 caracteres base64url." >&2; fallos=1; }
  [[ "$CLUSTER_TOKEN" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || { echo "❌ FIP_CLUSTER_TOKEN debe tener 32-128 caracteres base64url." >&2; fallos=1; }
  [[ "$SESSION_SECRET" != "$CLUSTER_TOKEN" ]] || { echo "❌ Los secretos de sesiones y clúster deben ser distintos." >&2; fallos=1; }
  [[ "$IMAGE_REPOSITORY" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] || { echo "❌ FIP_IMAGE_REPOSITORY no es válido." >&2; fallos=1; }
  if [[ -n "$IMAGE_DIGEST" ]]; then
    [[ "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || { echo "❌ FIP_IMAGE_DIGEST debe ser un digest sha256 completo." >&2; fallos=1; }
  elif [[ -z "$DRY" ]]; then
    echo "❌ Falta FIP_IMAGE_DIGEST: un despliegue real no confía en una etiqueta mutable." >&2
    fallos=1
  fi
  [[ "$LEGACY_IMAGE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || { echo "❌ FIP_IMAGE_NAME no es válido." >&2; fallos=1; }
  [[ "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || { echo "❌ VERSION no contiene una versión segura." >&2; fallos=1; }
  [[ "$CONTENEDOR" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo "❌ FIP_CONTAINER_NAME no es válido." >&2; fallos=1; }
  [[ "$DIR_BOOT" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ \
      && "$DIR_BOOT" != *"/../"* && "$DIR_BOOT" != *"/.." \
      && "$DIR_BOOT" != *"/./"* && "$DIR_BOOT" != *"/." ]] \
    || { echo "❌ FIP_DATA_DIR debe ser una ruta absoluta segura y normalizada." >&2; fallos=1; }
  [[ "$DIR_BOOT" != "/boot" && "$DIR_BOOT" != /boot/* ]] || { echo "❌ FIP_DATA_DIR no puede estar bajo /boot: keepalived.conf contiene la clave VRRP." >&2; fallos=1; }
  [[ "$TX_ROOT" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ \
      && "$TX_ROOT" != / && "$TX_ROOT" != /boot && "$TX_ROOT" != /boot/* \
      && "$TX_ROOT" != *"/../"* && "$TX_ROOT" != *"/.." \
      && "$TX_ROOT" != *"/./"* && "$TX_ROOT" != *"/." ]] \
    || { echo "❌ FIP_TRANSACTION_ROOT debe ser una ruta absoluta segura fuera de /boot." >&2; fallos=1; }
  [[ "$TX_ROOT" != "$DIR_BOOT" && "$TX_ROOT" != "$DIR_BOOT/"* \
      && "$DIR_BOOT" != "$TX_ROOT/"* ]] \
    || { echo "❌ FIP_TRANSACTION_ROOT y FIP_DATA_DIR deben ser árboles separados." >&2; fallos=1; }
  [[ "$REMOTE_SECRETS_DIR" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ \
      && "$REMOTE_SECRETS_DIR" != *"/../"* && "$REMOTE_SECRETS_DIR" != *"/.." \
      && "$REMOTE_SECRETS_DIR" != *"/./"* && "$REMOTE_SECRETS_DIR" != *"/." ]] \
    || { echo "❌ FIP_REMOTE_SECRETS_DIR debe ser una ruta absoluta segura y normalizada." >&2; fallos=1; }
  [[ "$REMOTE_SECRETS_DIR" != "/boot" && "$REMOTE_SECRETS_DIR" != /boot/* ]] || { echo "❌ Los secretos remotos no pueden guardarse en /boot (FAT no conserva permisos)." >&2; fallos=1; }
  [[ "$REMOTE_SECRETS_DIR" != "$DIR_BOOT" \
      && "$REMOTE_SECRETS_DIR" != "$DIR_BOOT/"* \
      && "$DIR_BOOT" != "$REMOTE_SECRETS_DIR/"* ]] || {
    echo "❌ FIP_DATA_DIR y FIP_REMOTE_SECRETS_DIR deben ser árboles separados; /datos es escribible." >&2
    fallos=1
  }
  [[ "$PLANTILLAS" =~ ^/[A-Za-z0-9._/@+-]+(/[A-Za-z0-9._/@+-]+)*$ && "$PLANTILLAS" != *"/../"* && "$PLANTILLAS" != *"/.." ]] || { echo "❌ FIP_TEMPLATE_DIR debe ser una ruta absoluta segura." >&2; fallos=1; }
  [[ "$PLANTILLA_NOMBRE" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo "❌ FIP_TEMPLATE_NAME no es válido." >&2; fallos=1; }
  for par_rutas in \
      "$TX_ROOT|$REMOTE_SECRETS_DIR" \
      "$PLANTILLAS|$DIR_BOOT" \
      "$PLANTILLAS|$REMOTE_SECRETS_DIR" \
      "$PLANTILLAS|$TX_ROOT"; do
    ruta_a="${par_rutas%%|*}"; ruta_b="${par_rutas#*|}"
    rutas_disjuntas "$ruta_a" "$ruta_b" || {
      echo "❌ Datos, secretos, plantillas y journal deben ser árboles disjuntos." >&2
      fallos=1
    }
  done
  if [[ "$VIP_PREFIJO" != "24" ]]; then
    echo "❌ La versión $APP_VERSION exige FIP_VIP_PREFIX=24; DHCP_DESDE se define por último octeto." >&2; fallos=1
  fi
  if ! entero_decimal_canonico "$DHCP_DESDE" \
      || ! (( 10#$DHCP_DESDE >= 1 && 10#$DHCP_DESDE <= 254 )); then
    echo "❌ DHCP_DESDE debe estar entre 1 y 254." >&2; fallos=1
  fi
  if ! entero_decimal_canonico "$PUERTO_POR_OMISION" \
      || ! (( 10#$PUERTO_POR_OMISION >= 1 && 10#$PUERTO_POR_OMISION <= 65535 )); then
    echo "❌ FIP_PUERTO debe estar entre 1 y 65535." >&2; fallos=1
  fi
  if ! entero_decimal_canonico "$PREEMPT_DELAY" \
      || ! (( 10#$PREEMPT_DELAY >= 0 && 10#$PREEMPT_DELAY <= 1000 )); then
    echo "❌ PREEMPT_DELAY debe ser un entero decimal entre 0 y 1000 segundos." >&2
    fallos=1
  fi
  if ! entero_decimal_canonico "$SSH_CONNECT_TIMEOUT" \
      || ! (( 10#$SSH_CONNECT_TIMEOUT >= 1 && 10#$SSH_CONNECT_TIMEOUT <= 120 )); then
    echo "❌ FIP_SSH_CONNECT_TIMEOUT debe estar entre 1 y 120 segundos." >&2
    fallos=1
  fi
  if ! entero_decimal_canonico "$SSH_TOTAL_TIMEOUT" \
      || ! (( 10#$SSH_TOTAL_TIMEOUT >= 10 && 10#$SSH_TOTAL_TIMEOUT <= 1800 )); then
    echo "❌ FIP_SSH_TOTAL_TIMEOUT debe estar entre 10 y 1800 segundos." >&2
    fallos=1
  fi
  if ! entero_decimal_canonico "$SSH_CLOCK_SKEW_MAX" \
      || ! (( 10#$SSH_CLOCK_SKEW_MAX >= 1 && 10#$SSH_CLOCK_SKEW_MAX <= 30 )); then
    echo "❌ FIP_SSH_CLOCK_SKEW_MAX debe estar entre 1 y 30 segundos." >&2
    fallos=1
  fi
  if ! entero_decimal_canonico "$SSH_CLOCK_RTT_MAX" \
      || ! (( 10#$SSH_CLOCK_RTT_MAX >= 1 && 10#$SSH_CLOCK_RTT_MAX <= 10 )); then
    echo "❌ FIP_SSH_CLOCK_RTT_MAX debe estar entre 1 y 10 segundos." >&2
    fallos=1
  fi
  local nodos_count=0
  for entrada in "${NODOS[@]}"; do
    (( nodos_count += 1 ))
    IFS=: read -r nombre ip iface prioridad clave <<< "$entrada"
    [[ -n "$nombre" && -n "$ip" && -n "$iface" && -n "$prioridad" && -n "$clave" ]] || { echo "❌ Entrada incompleta en NODOS: «$entrada»" >&2; fallos=1; continue; }
    [[ "$nombre" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "❌ Nombre de nodo no válido: $nombre" >&2; fallos=1; }
    ipv4_host_unicast_24 "$ip" \
      || { echo "❌ IP de gestión no válida en $nombre: $ip" >&2; fallos=1; }
    [[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo "❌ Interfaz no válida en $nombre: $iface" >&2; fallos=1; }
    if ! entero_decimal_canonico "$prioridad" \
        || ! (( 10#$prioridad >= 1 && 10#$prioridad <= 254 )); then
      echo "❌ Prioridad VRRP no válida en $nombre: $prioridad" >&2; fallos=1
    fi
    [[ "$clave" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "❌ Nombre de clave SSH no válido en $nombre." >&2; fallos=1; }
    case " $nodos_vistos " in *" $nombre "*) echo "❌ Nombre de nodo repetido: $nombre" >&2; fallos=1 ;; esac
    nodos_vistos="$nodos_vistos $nombre"
    case " $ips_nodos_vistas " in *" $ip "*) echo "❌ IP de gestión repetida: $ip" >&2; fallos=1 ;; esac
    ips_nodos_vistas="$ips_nodos_vistas $ip"
    case " $prioridades_vistos " in *" $prioridad "*) echo "❌ Prioridad VRRP repetida: $prioridad" >&2; fallos=1 ;; esac
    prioridades_vistos="$prioridades_vistos $prioridad"
  done
  (( nodos_count >= 2 )) || { echo "❌ La alta disponibilidad necesita al menos dos nodos." >&2; fallos=1; }
  (( nodos_count <= 16 )) || { echo "❌ La versión $APP_VERSION admite como máximo 16 nodos." >&2; fallos=1; }

  local -a registros_configurados=()
  local registro_configurado clave_registro valor_registro
  IFS=',' read -r -a registros_configurados <<< "$REGISTROS_POR_NODO"
  for registro_configurado in "${registros_configurados[@]}"; do
    [[ -z "$registro_configurado" ]] && continue
    [[ "$registro_configurado" == *=* ]] || { echo "❌ Registro por nodo inválido: $registro_configurado" >&2; fallos=1; continue; }
    clave_registro="${registro_configurado%%=*}"
    valor_registro="${registro_configurado#*=}"
    [[ " $nodos_vistos " == *" $clave_registro "* ]] || { echo "❌ Registro configurado para un nodo desconocido: $clave_registro" >&2; fallos=1; }
    [[ "$valor_registro" =~ ^[A-Za-z0-9][A-Za-z0-9_.:/-]*$ ]] || { echo "❌ Endpoint de Registry no válido para $clave_registro." >&2; fallos=1; }
  done

  if [[ -d "$SECRETS_DIR" && ! -L "$SECRETS_DIR" \
      && "$(readlink -f -- "$SECRETS_DIR")" == "$SECRETS_DIR" \
      && "$(stat -c '%u:%a' -- "$SECRETS_DIR")" == "$(id -u):700" ]]; then
    for entrada in "${NODOS[@]}"; do
      IFS=: read -r nombre _ _ _ clave <<< "$entrada"
      fichero_privado_local_seguro "$SECRETS_DIR/$clave" \
        || { echo "❌ La clave SSH de $nombre debe ser propia, canónica, 0600 y sin enlaces." >&2; fallos=1; }
    done
  else
    echo "❌ SECRETS_DIR debe ser un directorio propio, canónico y 0700: $SECRETS_DIR" >&2
    fallos=1
  fi

  case " $PUERTOS_VETADOS " in
    *" $PUERTO_POR_OMISION "*)
      echo "❌ El puerto $PUERTO_POR_OMISION esta en la lista negra de los navegadores." >&2
      echo "   Responderia por curl pero Chrome y Firefox se negarian a abrirlo (ERR_UNSAFE_PORT)." >&2
      fallos=1 ;;
  esac

  [[ ${#DIRECCIONES[@]} -gt 0 ]] || { echo "❌ El manifiesto no declara ninguna direccion." >&2; return 1; }
  (( ${#DIRECCIONES[@]} <= 64 )) || {
    echo "❌ La versión $APP_VERSION admite como máximo 64 direcciones por clúster." >&2
    return 1
  }

  for entrada in "${DIRECCIONES[@]}"; do
    if (( ${#entrada} > MAX_ENTRADA_DIRECCION )); then
      echo "❌ Una entrada de DIRECCIONES supera el máximo de $MAX_ENTRADA_DIRECCION caracteres." >&2
      fallos=1
      continue
    fi
    IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$entrada"

    [[ -n "$nombre" && -n "$vip" && -n "$vrid" && -n "$puerto" && -n "$ruta" ]] || {
      echo "❌ Entrada incompleta en el manifiesto: «$entrada»" >&2
      echo "   Formato: nombre:ip:vrid:puerto:ruta" >&2; fallos=1; continue
    }
    [[ "$nombre" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "❌ Nombre de servicio no válido: $nombre" >&2; fallos=1; }

    case " $nombres_vistos " in *" $nombre "*) echo "❌ Nombre repetido en el manifiesto: $nombre" >&2; fallos=1 ;; esac
    nombres_vistos="$nombres_vistos $nombre"

    identificador="$(identificador_vrrp "$nombre")"
    case " $identificadores_vrrp " in
      *" $identificador "*)
        echo "❌ Dos servicios producen el mismo identificador VRRP: $identificador" >&2
        fallos=1 ;;
    esac
    identificadores_vrrp="$identificadores_vrrp $identificador"

    case " $vrids " in *" $vrid "*) echo "❌ vrid $vrid repetido ($nombre). Dos grupos VRRP no pueden compartirlo: se pelearian por las direcciones del otro." >&2; fallos=1 ;; esac
    vrids="$vrids $vrid"

    case " $vips " in *" $vip "*) echo "❌ Direccion repetida en el manifiesto: $vip ($nombre)" >&2; fallos=1 ;; esac
    vips="$vips $vip"

    if ! entero_decimal_canonico "$vrid" \
        || ! (( 10#$vrid >= 1 && 10#$vrid <= 255 )); then
      echo "❌ vrid fuera de rango en $nombre: «$vrid» (VRRP admite 1-255)" >&2; fallos=1
    fi
    ipv4_host_unicast_24 "$vip" \
      || { echo "❌ La VIP de $nombre no es una dirección host unicast válida /24: $vip" >&2; fallos=1; }
    for nd in "${NODOS[@]}"; do
      IFS=: read -r _ ip _ _ _ <<< "$nd"
      [[ "$vip" != "$ip" ]] || {
        echo "❌ La VIP de $nombre coincide con la IP de gestión de un nodo: $vip" >&2
        fallos=1
      }
    done
    if ! entero_decimal_canonico "$puerto" \
        || ! (( 10#$puerto >= 1 && 10#$puerto <= 65535 )); then
      echo "❌ Puerto de salud no válido en $nombre: $puerto" >&2; fallos=1
    fi
    (( ${#ruta} <= MAX_RUTA_CHEQUEO )) \
      || { echo "❌ La ruta de salud de $nombre supera $MAX_RUTA_CHEQUEO caracteres." >&2; fallos=1; }
    [[ "$ruta" =~ $RUTA_RE ]] || { echo "❌ Ruta de salud no válida en $nombre: $ruta" >&2; fallos=1; }

    ultimo="${vip##*.}"
    [[ "$ultimo" =~ ^[0-9]+$ ]] || { echo "❌ Direccion mal formada en $nombre: $vip" >&2; fallos=1; continue; }
    (( 10#$ultimo < 10#$DHCP_DESDE )) || {
      echo "❌ $vip ($nombre) cae dentro del rango del DHCP (empieza en .$DHCP_DESDE). Elige otra." >&2; fallos=1; }

    [[ "$ruta" == /* ]] || { echo "❌ La ruta de chequeo de $nombre debe empezar por «/»: «$ruta»" >&2; fallos=1; }

    if [[ -n "$preferente" && "$preferente" != "-" ]]; then
      local conocido=""
      for nd in "${NODOS[@]}"; do [[ "${nd%%:*}" == "$preferente" ]] && conocido=1; done
      [[ -n "$conocido" ]] || { echo "❌ $nombre prefiere «$preferente», que no es ninguno de los nodos declarados." >&2; fallos=1; }
    fi
  done

  return $fallos
}

echo "· validando el manifiesto"
validar
printf '  %d direccion(es): ' "${#DIRECCIONES[@]}"
for e in "${DIRECCIONES[@]}"; do printf '%s(%s/vrid %s) ' "${e%%:*}" "$(echo "$e" | cut -d: -f2)" "$(echo "$e" | cut -d: -f3)"; done
echo

# ─────────────────────────────────────────────────────────────────────────────
# Configuracion VRRP de un nodo: cabecera comun y un bloque por direccion.
# ─────────────────────────────────────────────────────────────────────────────
# La prioridad de un nodo PARA UNA DIRECCION concreta. Si esa direccion tiene
# servidor preferido, el preferido va primero y se lleva la prioridad mas alta;
# los demas conservan su orden del manifiesto. Asi cada direccion puede preferir
# un servidor distinto y repartirse la carga en reposo.
declare -A NORMAL_PARA=()
declare -A FALLBACK_PARA=()
declare -A CARGA=()

menos_cargado_de() {
  local excluido="${1:-}" mejor="" mejor_carga=999999 entrada nombre carga
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre _ _ _ _ <<< "$entrada"
    [[ "$nombre" == "$excluido" ]] && continue
    carga="${CARGA[$nombre]:-0}"
    if (( carga < mejor_carga )) || {
      (( carga == mejor_carga )) && { [[ -z "$mejor" || "$nombre" < "$mejor" ]]; };
    }; then
      mejor="$nombre"
      mejor_carga="$carga"
    fi
  done
  printf '%s' "$mejor"
}

calcular_reparto() {
  local entrada nodo_entrada direccion_entrada nombre vip vrid puerto ruta preferente fallido destino objetivo
  CARGA=()
  NORMAL_PARA=()
  FALLBACK_PARA=()
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre _ _ _ _ <<< "$entrada"
    CARGA["$nombre"]=0
  done

  for entrada in "${DIRECCIONES[@]}"; do
    IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$entrada"
    if [[ -n "$preferente" && "$preferente" != "-" ]]; then
      destino="$preferente"
    else
      destino="$(menos_cargado_de)"
    fi
    NORMAL_PARA["$nombre"]="$destino"
    CARGA["$destino"]=$(( ${CARGA[$destino]:-0} + 1 ))
  done

  for nodo_entrada in "${NODOS[@]}"; do
    IFS=: read -r fallido _ _ _ _ <<< "$nodo_entrada"
    CARGA=()
    for entrada in "${NODOS[@]}"; do
      IFS=: read -r nombre _ _ _ _ <<< "$entrada"
      CARGA["$nombre"]=0
    done
    for direccion_entrada in "${DIRECCIONES[@]}"; do
      IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$direccion_entrada"
      destino="${NORMAL_PARA[$nombre]}"
      [[ "$destino" == "$fallido" ]] || CARGA["$destino"]=$(( ${CARGA[$destino]:-0} + 1 ))
    done
    for direccion_entrada in "${DIRECCIONES[@]}"; do
      IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$direccion_entrada"
      destino="${NORMAL_PARA[$nombre]}"
      [[ "$destino" == "$fallido" ]] || continue
      objetivo="$(menos_cargado_de "$fallido")"
      FALLBACK_PARA["$nombre|$fallido"]="$objetivo"
      CARGA["$objetivo"]=$(( ${CARGA[$objetivo]:-0} + 1 ))
    done
  done
}

calcular_reparto

prioridad_para() {  # <nodo> <servicio>
  local nodo="$1" servicio="$2" i e orden=() prios=() nombre
  local destino clave respaldo
  destino="${NORMAL_PARA[$servicio]:-}"
  clave="$servicio|$destino"
  respaldo="${FALLBACK_PARA[$clave]:-}"
  # Las prioridades son niveles disponibles, no una segunda fuente de orden.
  # Se asignan de mayor a menor al destino, respaldo y resto, aunque el
  # manifiesto declare los nodos en un orden distinto al valor numérico.
  mapfile -t prios < <(
    for e in "${NODOS[@]}"; do
      IFS=: read -r _ _ _ prioridad _ <<< "$e"
      printf '%s\n' "$prioridad"
    done | sort -nr
  )
  [[ -n "$destino" ]] && orden+=("$destino")
  [[ -n "$respaldo" && "$respaldo" != "$destino" ]] && orden+=("$respaldo")
  for e in "${NODOS[@]}"; do
    nombre="${e%%:*}"
    [[ "$nombre" == "$destino" || "$nombre" == "$respaldo" ]] && continue
    orden+=("$nombre")
  done
  for i in "${!orden[@]}"; do
    [[ "${orden[$i]}" == "$nodo" ]] && { echo "${prios[$i]:-50}"; return; }
  done
  echo 50
}

config_for() {  # <interfaz> <nodo>
  local iface="$1" nodo="$2" nombre vip vrid puerto ruta preferente prio bloque_pref identificador
  cat <<CONF
# GENERADO por floating-ip/deploy-floating-ip.sh — no editar a mano.
# Cualquier cambio aqui se pierde en el siguiente despliegue; se toca el
# manifiesto de la instalación y se vuelve a desplegar.

global_defs {
    # Sin esto keepalived busca un usuario 'keepalived_script' que no existe y
    # lo deja dicho en cada arranque.
    script_user root
    enable_script_security
}
CONF
  for entrada in "${DIRECCIONES[@]}"; do
    IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$entrada"
    prio="$(prioridad_para "$nodo" "$nombre")"
    identificador="$(identificador_vrrp "$nombre")"
    if [[ -z "$preferente" || "$preferente" == "-" ]]; then
      bloque_pref="    # Sin servidor preferido: cuando un nodo vuelve, no arrebata la direccion
    # al que la esta sirviendo bien. Un salto de mas es un corte de mas.
    nopreempt"
    else
      bloque_pref="    # Prefiere «$preferente»: la direccion vuelve alli en cuanto vuelve a estar
    # sano. El retardo evita que un arranque se la quite a quien la esta
    # sirviendo antes de estar listo de verdad; se suma a los dos chequeos
    # seguidos que ya hacen falta para darse por sano.
    preempt_delay ${PREEMPT_DELAY:-45}"
    fi
    cat <<CONF

# «Sano» = $nombre contesta EN ESTE NODO, no solo que la maquina este viva. El
# guion vive DENTRO de la imagen: montado desde /boot no vale, porque el USB es
# FAT y no guarda el bit de ejecución; keepalived lo detectaría, desactivaría
# el chequeo y el nodo conservaría la dirección aunque no sirviera nada.
#
# El nombre del servicio va como primer argumento para que el chequeo pueda
# mirar si esta drenado: con la marca puesta falla a proposito y este nodo cede
# la direccion, que es como se vacia un servidor para mantenimiento.
vrrp_script comprobar_$identificador {
    script  "/usr/local/bin/check-http $nombre http://127.0.0.1:$puerto$ruta"
    interval 5
    timeout  4
    rise     2
    fall     2
    weight   0
}

vrrp_instance $identificador {
    state           BACKUP
    interface       $iface
    virtual_router_id $vrid
    priority        $prio
    advert_int      1
$bloque_pref
    authentication {
        auth_type PASS
        auth_pass $VRRP_AUTH_PASS
    }
    virtual_ipaddress {
        $vip/$VIP_PREFIJO dev $iface
    }
    track_script {
        comprobar_$identificador
    }
}
CONF
  done
}

# Los pares de un nodo: los paneles de los demás nodos.
declare -A PUERTO_POR_NODO_REAL=()
pares_de() {  # <nodo> <puerto>
  local yo="$1" puerto="$2" salida="" nombre ip puerto_destino
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre ip _ _ _ <<< "$entrada"
    [[ "$nombre" == "$yo" ]] && continue
    puerto_destino="${PUERTO_POR_NODO_REAL[$nombre]:-$puerto}"
    salida="${salida:+$salida,}http://$ip:$puerto_destino"
  done
  echo "$salida"
}

# Devuelve la imagen completa para un nodo. La fuente pública no depende de que
# exista antes un Registry local. Un mapping explícito conserva despliegues con
# mirrors privados sin incrustarlos en el producto compartido.
imagen_para() {
  local destino="$1" entrada clave valor
  local -a configurados=()
  IFS=',' read -r -a configurados <<< "$REGISTROS_POR_NODO"
  for entrada in "${configurados[@]}"; do
    [[ "$entrada" == *=* ]] || continue
    clave="${entrada%%=*}"; valor="${entrada#*=}"
    [[ "$clave" == "$destino" && -n "$valor" ]] && {
      printf '%s/%s@%s\n' "${valor%/}" "$LEGACY_IMAGE_NAME" "$IMAGE_DIGEST"
      return
    }
  done
  printf '%s@%s\n' "$IMAGE_REPOSITORY" "$IMAGE_DIGEST"
}

# La tabla de nodos que necesita el panel para calcular sucesores.
tabla_nodos() {
  local salida="" nombre ip iface prio
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre ip iface prio _ <<< "$entrada"
    salida="${salida:+$salida,}$nombre:$ip:$iface:$prio"
  done
  echo "$salida"
}

# ¿A que nodos vamos?
SELECCION=()
if [[ ${#OBJETIVOS[@]} -eq 0 ]]; then
  for entrada in "${NODOS[@]}"; do SELECCION+=("$entrada"); done
else
  for obj in "${OBJETIVOS[@]}"; do
    encontrado=""
    for entrada in "${NODOS[@]}"; do
      [[ "${entrada%%:*}" == "$obj" ]] && { SELECCION+=("$entrada"); encontrado=1; }
    done
    [[ -n "$encontrado" ]] || { echo "❌ Nodo desconocido: $obj" >&2; exit 2; }
  done
fi

if [[ -n "$FRESH_INSTALL" && ${#OBJETIVOS[@]} -ne 0 ]]; then
  echo "❌ --fresh-install sólo admite el clúster completo, sin nombres de nodo." >&2
  exit 2
fi

declare -A NODOS_SELECCIONADOS=()
for entrada in "${SELECCION[@]}"; do
  nombre_seleccionado="${entrada%%:*}"
  [[ -z "${NODOS_SELECCIONADOS[$nombre_seleccionado]:-}" ]] || {
    echo "❌ Nodo seleccionado más de una vez: $nombre_seleccionado" >&2
    exit 2
  }
  NODOS_SELECCIONADOS["$nombre_seleccionado"]=1
done

if [[ -n "$DRY" ]]; then
  echo "· configuracion que se escribiria (simulacion)"
  for entrada in "${SELECCION[@]}"; do
    IFS=: read -r nombre ip iface prio clave <<< "$entrada"
    echo "  ── $nombre (orden base $prio, interfaz $iface) ──"
    config_for "$iface" "$nombre" \
      | sed -E 's/^([[:space:]]*auth_pass)[[:space:]]+.*/\1 ********/' \
      | sed 's/^/    | /'
    echo "    | panel: puerto $PUERTO_POR_OMISION, pares $(pares_de "$nombre" "$PUERTO_POR_OMISION")"
  done
  [[ -z "$FRESH_INSTALL" ]] \
    || echo "(simulación: la vaciedad remota para --fresh-install aún no se ha comprobado)"
  echo "(simulacion: no se ha tocado ningun nodo)"
  exit 0
fi

# Esta versión sólo admite una cohorte N/N. Permitir una selección parcial
# dejaría sin barrera a peers que comparten el mismo estado y los mismos
# secretos, por lo que no es una actualización transaccional del clúster.
if (( ${#OBJETIVOS[@]} != 0 || ${#SELECCION[@]} != ${#NODOS[@]} )); then
  echo "❌ El despliegue real de $APP_VERSION exige seleccionar el clúster completo (N/N)." >&2
  exit 2
fi

[[ -f "$TX_LIB" && ! -L "$TX_LIB" && -r "$TX_LIB" ]] || {
  echo "❌ No existe la biblioteca transaccional local esperada." >&2
  exit 2
}
for utilidad_local in bash timeout ssh ssh-keygen python3 curl sha256sum stat \
    readlink base64 od tr date tar grep sed cut mktemp find rmdir basename; do
  command -v "$utilidad_local" >/dev/null 2>&1 || {
    echo "❌ Falta una capacidad local necesaria para el despliegue seguro." >&2
    exit 2
  }
done

validar_known_hosts() {
  local fichero="$1" modo uid_actual
  [[ "$fichero" == /* && -f "$fichero" && ! -L "$fichero" \
      && "$(readlink -f -- "$fichero")" == "$fichero" \
      && "$(stat -c %h -- "$fichero")" == 1 ]] || return 1
  uid_actual="$(id -u)"
  [[ "$(stat -c %u -- "$fichero")" == "$uid_actual" ]] || return 1
  modo="$(stat -c %a -- "$fichero")"
  [[ "$modo" == 600 || "$modo" == 644 ]]
}

validar_known_hosts "$KNOWN_HOSTS_FILE" || {
  echo "❌ FIP_KNOWN_HOSTS_FILE debe ser un fichero regular propio, 0600/0644 y sin enlaces." >&2
  exit 2
}
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip _ _ _ <<< "$entrada"
  ssh-keygen -F "$ip" -f "$KNOWN_HOSTS_FILE" >/dev/null 2>&1 || {
    echo "❌ $nombre no está acreditado previamente en known_hosts; no se usará accept-new." >&2
    exit 2
  }
done

# Construye todas las llamadas SSH desde un único contrato. timeout sólo envía
# TERM: el journal remoto permite reanudar si la sesión se corta a mitad de una
# operación, sin escalar a KILL ni confiar en una shell interactiva.
ssh_para() { # <clave> <ip> <nombre-array>
  local clave="$1" ip="$2" destino="$3"
  local -n salida="$destino"
  fichero_privado_local_seguro "$SECRETS_DIR/$clave" || {
    echo "❌ La clave SSH dejó de cumplir el contrato privado local." >&2
    return 1
  }
  salida=(
    timeout --foreground --signal=TERM "${SSH_TOTAL_TIMEOUT}s"
    ssh -T -i "$SECRETS_DIR/$clave"
    -o BatchMode=yes -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS_FILE"
    -o "ConnectTimeout=$SSH_CONNECT_TIMEOUT" -o ConnectionAttempts=1
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2
    "root@$ip"
  )
}

tx_funcion_permitida() {
  case "$1" in
    fip_tx_begin|fip_tx_discover|fip_tx_recovery_action|fip_tx_phase|\
    fip_tx_prepare_paths|fip_tx_set_mode|fip_tx_get_mode|fip_tx_baseline|\
    fip_tx_install_freeze|fip_tx_snapshot|fip_tx_preserve_container|\
    fip_tx_snapshot_quiesced|fip_tx_discover_candidate|fip_tx_record_candidate|\
    fip_tx_abort_unprepared|fip_tx_abort_pre_mutation|\
    fip_tx_rollback_quiesce|fip_tx_rollback_restore|fip_tx_rollback_restart|\
    fip_tx_mark_verified|fip_tx_decide_commit|fip_tx_install_template|\
    fip_tx_mark_committed|fip_tx_cleanup) return 0 ;;
    *) return 1 ;;
  esac
}

tx_remoto() { # <clave> <ip> <función> [args...]
  local clave="$1" ip="$2" funcion="$3" argumento
  local -a SSH_TX=()
  shift 3
  tx_funcion_permitida "$funcion" || return 1
  ssh_para "$clave" "$ip" SSH_TX
  {
    cat -- "$TX_LIB"
    printf '\nset --'
    for argumento in "$@"; do printf ' %q' "$argumento"; done
    printf '\n%s "$@"\n' "$funcion"
  } | "${SSH_TX[@]}" bash -s
}

tx_preparar_almacen_remoto() { # <clave> <ip> <txid>
  local clave="$1" ip="$2" txid="$3" argumento
  local -a SSH_TX=()
  ssh_para "$clave" "$ip" SSH_TX
  {
    cat -- "$TX_LIB"
    declare -f preparar_almacen_persistente
    printf '\nset --'
    for argumento in "$DIR_BOOT" "$TX_ROOT" "$txid" "$PLANTILLA"; do
      printf ' %q' "$argumento"
    done
    printf '\npreparar_almacen_persistente "$@"\n'
  } | "${SSH_TX[@]}" bash -s
}

tx_stage_template_remoto() { # <clave> <ip> <txid> <fichero-local>
  local clave="$1" ip="$2" txid="$3" fichero="$4" argumento
  local -a SSH_TX=()
  ssh_para "$clave" "$ip" SSH_TX
  {
    cat -- "$TX_LIB"
    printf '\nset --'
    for argumento in "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA"; do
      printf ' %q' "$argumento"
    done
    printf '\nbase64 -d <<\047FIP_TEMPLATE_PAYLOAD\047 | fip_tx_stage_template "$@"\n'
    base64 "$fichero"
    printf '%s\n' FIP_TEMPLATE_PAYLOAD
  } | "${SSH_TX[@]}" bash -s
}

TX_ACTIVA=""
TX_EN_RECOVERY=""

recuperar_transaccion_cluster_impl() {
  local entrada nombre ip clave descubrimiento txid="" actual fase decision
  local modo baseline hay_commit="" completos=0 rollback_iniciado=""
  local evidencia cid_recuperado imagen_id_recuperada digest_recuperado
  local digest_decidido=""
  local writer="${NODOS[0]%%:*}"
  local -a activos=() inactivos=()
  declare -A FASE=() MODO=()

  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre ip _ _ clave <<< "$entrada"
    descubrimiento="$(tx_remoto "$clave" "$ip" fip_tx_discover "$TX_ROOT")" \
      || return 1
    if [[ "$descubrimiento" == none ]]; then
      inactivos+=("$entrada")
      continue
    fi
    [[ "$descubrimiento" =~ ^txid=([0-9a-f]{32})\;phase=([a-z-]+)\;decision=(none|commit)$ ]] \
      || return 1
    actual="${BASH_REMATCH[1]}"; fase="${BASH_REMATCH[2]}"; decision="${BASH_REMATCH[3]}"
    [[ -z "$txid" || "$txid" == "$actual" ]] || {
      echo "❌ Hay transacciones distintas activas; se requiere intervención segura." >&2
      return 1
    }
    txid="$actual"; activos+=("$entrada")
    FASE["$nombre"]="$fase"
    [[ "$decision" != commit ]] || hay_commit=1
    [[ "$fase" != rolling-back && "$fase" != rolled-back ]] || rollback_iniciado=1
  done
  if [[ -z "$txid" ]]; then
    TX_ACTIVA=""; return 0
  fi

  echo "· recuperando una transacción de despliegue interrumpida"
  if [[ -n "$hay_commit" ]]; then
    # La release solicitada por esta nueva invocación no participa en recovery.
    # La evidencia del commit anterior vive en los propios candidatos: TXID,
    # CID, image ID y RepoDigest fijado por label. Así un rerun que ya solicite
    # otro digest termina primero la saga antigua, sin hacer rollback ni atascarla.
    for entrada in "${NODOS[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      ssh_para "$clave" "$ip" SSH_RECOVERY_CHECK
      evidencia="$("${SSH_RECOVERY_CHECK[@]}" "set -euo pipefail
evidencia=\$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.Running}}|{{index .Config.Labels \"io.ezr43l.deploy-transaction\"}}|{{index .Config.Labels \"io.ezr43l.deploy-role\"}}|{{index .Config.Labels \"io.ezr43l.deploy-image-digest\"}}' '$CONTENEDOR')
IFS='|' read -r cid imagen running label_tx label_role digest <<EOF
\$evidencia
EOF
case \"\$cid\" in (*[!0-9a-f]*|'') exit 1;; esac
[ \"\${#cid}\" -eq 64 ]
case \"\$imagen\" in (sha256:????????????????????????????????????????????????????????????????) ;; (*) exit 1;; esac
[ \"\$running\" = true ]
[ \"\$label_tx\" = '$txid' ]
[ \"\$label_role\" = candidate ]
case \"\$digest\" in (sha256:????????????????????????????????????????????????????????????????) ;; (*) exit 1;; esac
case \"\${digest#sha256:}\" in (*[!0-9a-f]*) exit 1;; esac
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \"\$imagen\" \
  | grep -E -- \"@\${digest}\$\" >/dev/null
printf '%s|%s|%s\n' \"\$cid\" \"\$imagen\" \"\$digest\"")" || {
        echo "❌ $nombre no acredita el candidato de la transacción decidida." >&2
        return 1
      }
      [[ "$evidencia" =~ ^([0-9a-f]{64})\|(sha256:[0-9a-f]{64})\|(sha256:[0-9a-f]{64})$ ]] \
        || return 1
      cid_recuperado="${BASH_REMATCH[1]}"
      imagen_id_recuperada="${BASH_REMATCH[2]}"
      digest_recuperado="${BASH_REMATCH[3]}"
      [[ -n "$cid_recuperado" && -n "$imagen_id_recuperada" ]]
      [[ -z "$digest_decidido" || "$digest_decidido" == "$digest_recuperado" ]] || {
        echo "❌ Los candidatos del commit interrumpido no comparten RepoDigest." >&2
        return 1
      }
      digest_decidido="$digest_recuperado"
    done
    # Commit gana. Una decisión sólo puede publicarse tras verified N/N; se
    # replica primero desde el escritor y jamás se vuelve a rollback.
    for entrada in "${activos[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      case "${FASE[$nombre]}" in
        verified)
          [[ "$nombre" == "$writer" ]] || continue
          tx_remoto "$clave" "$ip" fip_tx_decide_commit "$TX_ROOT" "$txid" || return 1
          FASE["$nombre"]=commit-decided
          ;;
        commit-decided|committed) ;;
        *) echo "❌ Journal incompatible con una decisión commit durable." >&2; return 1 ;;
      esac
    done
    for entrada in "${activos[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      [[ "${FASE[$nombre]}" != verified ]] || {
        tx_remoto "$clave" "$ip" fip_tx_decide_commit "$TX_ROOT" "$txid" || return 1
        FASE["$nombre"]=commit-decided
      }
    done
    for entrada in "${activos[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      [[ "${FASE[$nombre]}" != committed ]] || continue
      tx_remoto "$clave" "$ip" fip_tx_install_template \
        "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA" || return 1
    done
    for entrada in "${activos[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      [[ "${FASE[$nombre]}" != committed ]] || continue
      tx_remoto "$clave" "$ip" fip_tx_mark_committed \
        "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA" || return 1
    done
  else
    # Sin decisión, el baseline global determina si existe una restauración
    # autorizada. Un modo aún ausente sólo puede ser begin/prepare pre-mutation.
    for entrada in "${activos[@]}"; do
      IFS=: read -r nombre ip _ _ clave <<< "$entrada"
      if modo="$(tx_remoto "$clave" "$ip" fip_tx_get_mode "$TX_ROOT" "$txid" 2>/dev/null)"; then
        baseline="$(tx_remoto "$clave" "$ip" fip_tx_baseline "$TX_ROOT" "$txid")" \
          || return 1
        MODO["$nombre"]="$modo"
        if [[ "$modo" == v2 && "$baseline" == snapshot ]] \
            || [[ "$modo" == legacy && "$baseline" == quiesced ]]; then
          (( completos += 1 ))
        fi
      else
        MODO["$nombre"]=""
      fi
    done
    if [[ -n "$rollback_iniciado" ]] \
        || (( ${#activos[@]} == ${#NODOS[@]} && completos == ${#NODOS[@]} )); then
      if [[ -n "$rollback_iniciado" ]]; then
        for entrada in "${inactivos[@]}"; do
          IFS=: read -r nombre ip _ _ clave <<< "$entrada"
          ssh_para "$clave" "$ip" SSH_RECOVERY_CHECK
          "${SSH_RECOVERY_CHECK[@]}" "set -euo pipefail
[ \"\$(docker inspect --format '{{.State.Running}}' '$CONTENEDOR')\" = true ]
[ \"\$(docker inspect --format '{{index .Config.Labels \"io.ezr43l.deploy-transaction\"}}' '$CONTENEDOR')\" != '$txid' ]
! docker inspect 'fip-rb-$txid' >/dev/null 2>&1" || {
            echo "❌ $nombre no acredita el rollback ya limpiado." >&2
            return 1
          }
        done
      fi
      for entrada in "${activos[@]}"; do
        IFS=: read -r nombre ip _ _ clave <<< "$entrada"
        [[ "${FASE[$nombre]}" != rolled-back ]] || continue
        tx_remoto "$clave" "$ip" fip_tx_rollback_quiesce "$TX_ROOT" "$txid" || return 1
      done
      for entrada in "${activos[@]}"; do
        IFS=: read -r nombre ip _ _ clave <<< "$entrada"
        [[ "${FASE[$nombre]}" != rolled-back ]] || continue
        tx_remoto "$clave" "$ip" fip_tx_rollback_restore \
          "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA" || return 1
      done
      for entrada in "${activos[@]}"; do
        IFS=: read -r nombre ip _ _ clave <<< "$entrada"
        [[ "${FASE[$nombre]}" != rolled-back ]] || continue
        tx_remoto "$clave" "$ip" fip_tx_rollback_restart \
          "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA" || return 1
      done
    else
      # La barrera N/N nunca autorizó mutaciones: no se restaura ningún
      # snapshot parcial (especialmente el preliminar legacy).
      for entrada in "${activos[@]}"; do
        IFS=: read -r nombre ip _ _ clave <<< "$entrada"
        [[ "${FASE[$nombre]}" != rolled-back ]] || continue
        if [[ -z "${MODO[$nombre]}" ]]; then
          tx_remoto "$clave" "$ip" fip_tx_abort_unprepared "$TX_ROOT" "$txid" || return 1
        else
          tx_remoto "$clave" "$ip" fip_tx_abort_pre_mutation \
            "$TX_ROOT" "$txid" "$DIR_BOOT" "$PLANTILLA" || return 1
        fi
      done
    fi
  fi
  for entrada in "${activos[@]}"; do
    IFS=: read -r nombre ip _ _ clave <<< "$entrada"
    [[ "$nombre" != "$writer" ]] || continue
    tx_remoto "$clave" "$ip" fip_tx_cleanup "$TX_ROOT" "$txid" || return 1
  done
  for entrada in "${activos[@]}"; do
    IFS=: read -r nombre ip _ _ clave <<< "$entrada"
    [[ "$nombre" == "$writer" ]] || continue
    tx_remoto "$clave" "$ip" fip_tx_cleanup "$TX_ROOT" "$txid" || return 1
  done
  TX_ACTIVA=""
}

recuperar_transaccion_cluster() {
  local estado
  [[ -z "$TX_EN_RECOVERY" ]] || return 1
  TX_EN_RECOVERY=1
  recuperar_transaccion_cluster_impl
  estado=$?
  TX_EN_RECOVERY=""
  return "$estado"
}

TABLA="$(tabla_nodos)"
[[ -f "$RENDERER" ]] || { echo "❌ No existe $RENDERER" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || {
  echo "❌ python3 es necesario para personalizar la plantilla de Unraid." >&2
  exit 2
}
command -v tar >/dev/null 2>&1 || {
  echo "❌ tar es necesario para transferir el preflight sin exponer el estado." >&2
  exit 2
}

echo "· comprobando capacidades y reloj de todos los hosts"
reloj_intervalo_inicializado=""
reloj_offset_inferior_max=0
reloj_offset_superior_min=0
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip _ _ clave <<< "$entrada"
  reloj_local_antes="$(date +%s)"
  [[ "$reloj_local_antes" =~ ^[0-9]{10,}$ ]] || {
    echo "❌ El reloj local no devuelve un epoch válido." >&2
    exit 2
  }
  ssh_para "$clave" "$ip" SSH_CAPACIDADES
  # shellcheck disable=SC2016  # el bloque se expande en el host remoto, no localmente
  capacidad="$("${SSH_CAPACIDADES[@]}" '
set -euo pipefail
for utilidad in bash docker ip curl stat sha256sum tar sync readlink base64 date \
    chown chmod cp mv ln rm rmdir mkdir wc sleep grep awk sed sort od find mktemp \
    cat tail seq tr install; do
  command -v "$utilidad" >/dev/null 2>&1
done
reloj=$(date +%s)
case "$reloj" in (*[!0-9]*|'') exit 1;; esac
printf "capability-ok;%s\n" "$reloj"
')" || {
    echo "❌ $nombre no acredita las capacidades remotas mínimas." >&2
    exit 1
  }
  reloj_local_despues="$(date +%s)"
  [[ "$reloj_local_despues" =~ ^[0-9]{10,}$ ]] || {
    echo "❌ El reloj local no devuelve un epoch válido." >&2
    exit 2
  }
  (( 10#$reloj_local_despues >= 10#$reloj_local_antes \
      && 10#$reloj_local_despues - 10#$reloj_local_antes \
        <= 10#$SSH_CLOCK_RTT_MAX )) || {
    echo "❌ La muestra de reloj no es monotónica o su RTT es demasiado amplio." >&2
    exit 1
  }
  [[ "$capacidad" =~ ^capability-ok\;([0-9]{10,})$ ]] || {
    echo "❌ $nombre devolvió una respuesta de capacidades no válida." >&2
    exit 1
  }
  reloj_remoto="${BASH_REMATCH[1]}"
  # El epoch remoto se obtuvo en algún instante entre ambas lecturas locales.
  # Comparar estos intervalos evita confundir tiempo secuencial/RTT con deriva.
  reloj_offset_inferior=$((10#$reloj_remoto - 10#$reloj_local_despues))
  reloj_offset_superior=$((10#$reloj_remoto - 10#$reloj_local_antes))
  if [[ -z "$reloj_intervalo_inicializado" ]]; then
    reloj_offset_inferior_max="$reloj_offset_inferior"
    reloj_offset_superior_min="$reloj_offset_superior"
    reloj_intervalo_inicializado=1
  else
    (( reloj_offset_inferior <= reloj_offset_inferior_max )) \
      || reloj_offset_inferior_max="$reloj_offset_inferior"
    (( reloj_offset_superior >= reloj_offset_superior_min )) \
      || reloj_offset_superior_min="$reloj_offset_superior"
  fi
done
(( reloj_offset_inferior_max - reloj_offset_superior_min \
    <= 10#$SSH_CLOCK_SKEW_MAX )) || {
  echo "❌ La deriva de reloj del clúster supera la ventana segura configurada." >&2
  exit 1
}

# Discovery/recovery precede a cualquier auditoría que considere residual el
# marker .deploy-freeze. La biblioteca viaja por stdin y no se instala en hosts.
recuperar_transaccion_cluster || {
  echo "❌ No se pudo recuperar de forma segura el despliegue anterior." >&2
  exit 1
}
HUELLA_MARCADOR_PROTOCOLO="$(python3 - "${NODOS[@]}" <<'PY'
import hashlib
import json
import sys

nombres = [entrada.split(":", 1)[0] for entrada in sys.argv[1:]]
contenido = json.dumps({
    "capabilities": ["pool-causal-v2", "security-causal-v2"],
    "nodos": nombres,
    "schema": 1,
}, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode() + b"\n"
print(hashlib.sha256(contenido).hexdigest())
PY
)"
[[ "$HUELLA_MARCADOR_PROTOCOLO" =~ ^[0-9a-f]{64}$ ]]

# Primera puerta externa: sólo lectura y sobre TODOS los nodos, no únicamente
# los seleccionados. Una divergencia aborta antes de pull, chmod, stop o rm.
declare -A HUELLAS_SECRETOS_LOCALES=(
  [vrrp]="$(printf '%s\n' "$VRRP_AUTH_PASS" | sha256sum | cut -d' ' -f1)"
  [session]="$(printf '%s\n' "$SESSION_SECRET" | sha256sum | cut -d' ' -f1)"
  [cluster]="$(printf '%s\n' "$CLUSTER_TOKEN" | sha256sum | cut -d' ' -f1)"
)
declare -A COPIAS_SECRETOS_REMOTAS=([vrrp]=0 [session]=0 [cluster]=0)
declare -A HUELLA_SECRETO_REMOTA=()
echo "· auditando la continuidad de secretos en todos los nodos"
ESCRITOR_ESPERADO="${NODOS[0]%%:*}"
declare -A PROTOCOLO_ACTUAL=()
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip iface prio clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH_AUDIT

  identidad_serializada="$(declare -f auditar_identidad_remota)"
  identidad_remota="$("${SSH_AUDIT[@]}" \
    "set -euo pipefail; $identidad_serializada; auditar_identidad_remota '$CONTENEDOR'")" || {
    echo "❌ $nombre: no se pudo auditar la identidad lógica existente." >&2
    exit 1
  }
  if [[ "$identidad_remota" != "absent" ]]; then
    [[ "$identidad_remota" =~ ^node=([A-Za-z0-9_-]+)\;writer=([A-Za-z0-9_-]+)\;protocol=(legacy|v2)$ ]] || {
      echo "❌ $nombre: respuesta de identidad remota no válida." >&2
      exit 1
    }
    [[ "${BASH_REMATCH[1]}" == "$nombre" ]] || {
      echo "❌ $nombre: el contenedor existente pertenece a '${BASH_REMATCH[1]}'." >&2
      exit 1
    }
    [[ "${BASH_REMATCH[2]}" == "$ESCRITOR_ESPERADO" ]] || {
      echo "❌ El orden de FIP_NODOS cambiaría el escritor de '${BASH_REMATCH[2]}' a '$ESCRITOR_ESPERADO'." >&2
      echo "   La identidad del escritor es inmutable; hace falta una migración explícita." >&2
      exit 1
    }
    PROTOCOLO_ACTUAL["$nombre"]="${BASH_REMATCH[3]}"
  else
    PROTOCOLO_ACTUAL["$nombre"]="absent"
  fi

  auditor_control_serializado="$(declare -f auditar_control_remoto)"
  resultado_control="$("${SSH_AUDIT[@]}" \
    "set -euo pipefail; $auditor_control_serializado; auditar_control_remoto \
      '$DIR_BOOT' '$CONTENEDOR' '$HUELLA_MARCADOR_PROTOCOLO' \
      '${PROTOCOLO_ACTUAL[$nombre]}'")" || {
    echo "❌ $nombre: el almacenamiento de control existente no supera la auditoría." >&2
    exit 1
  }
  [[ "$resultado_control" =~ ^marker=(absent|present)$ ]] || {
    echo "❌ $nombre: respuesta no válida al auditar el almacenamiento de control." >&2
    exit 1
  }

  auditor_artefacto_serializado="$(declare -f auditar_artefacto_actual_remoto)"
  artefacto_actual="$("${SSH_AUDIT[@]}" \
    "set -euo pipefail; $auditor_artefacto_serializado; auditar_artefacto_actual_remoto \
      '$CONTENEDOR' '$PLANTILLA' '${PROTOCOLO_ACTUAL[$nombre]}' '$APP_VERSION'")" || {
    echo "❌ $nombre: el artefacto actualmente instalado no es auditable." >&2
    exit 1
  }
  case "${PROTOCOLO_ACTUAL[$nombre]}" in
    absent|legacy)
      [[ "$artefacto_actual" == "artifact=${PROTOCOLO_ACTUAL[$nombre]}" ]] || {
        echo "❌ $nombre: respuesta no válida al auditar el artefacto actual." >&2
        exit 1
      }
      ;;
    v2)
      [[ "$artefacto_actual" =~ ^artifact=v2\;revision=([0-9a-f]{12,64})\;digest=([A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64})\;image=(sha256:[0-9a-f]{64})$ ]] || {
        echo "❌ $nombre: metadatos no válidos en el artefacto v2 instalado." >&2
        exit 1
      }
      ;;
  esac

  if [[ -n "$FRESH_INSTALL" ]]; then
    alta_serializada="$(declare -f comprobar_alta_fresca_remota)"
    "${SSH_AUDIT[@]}" \
      "set -euo pipefail; $alta_serializada; comprobar_alta_fresca_remota \
        '$DIR_BOOT' '$CONTENEDOR'"
  fi

  auditor_serializado="$(declare -f auditar_secretos_remotos)"
  resultado_auditoria="$("${SSH_AUDIT[@]}" \
    "set -euo pipefail; $auditor_serializado; auditar_secretos_remotos \
      '$REMOTE_SECRETS_DIR' '$CONTENEDOR'")" || {
    echo "❌ $nombre: no se pudieron auditar los secretos remotos." >&2
    exit 1
  }
  vistos_vrrp=0; vistos_session=0; vistos_cluster=0
  while IFS= read -r linea; do
    [[ "$linea" =~ ^(vrrp|session|cluster)=(missing|[0-9a-f]{64})$ ]] || {
      echo "❌ $nombre: respuesta no válida durante la auditoría de secretos." >&2
      exit 1
    }
    rol_auditado="${BASH_REMATCH[1]}"
    huella_auditada="${BASH_REMATCH[2]}"
    HUELLA_SECRETO_REMOTA["$nombre:$rol_auditado"]="$huella_auditada"
    case "$rol_auditado" in
      vrrp)
        (( vistos_vrrp == 0 )) || { echo "❌ $nombre: rol vrrp duplicado." >&2; exit 1; }
        vistos_vrrp=1
        ;;
      session)
        (( vistos_session == 0 )) || { echo "❌ $nombre: rol session duplicado." >&2; exit 1; }
        vistos_session=1
        ;;
      cluster)
        (( vistos_cluster == 0 )) || { echo "❌ $nombre: rol cluster duplicado." >&2; exit 1; }
        vistos_cluster=1
        ;;
    esac
    if [[ "$huella_auditada" != "missing" \
        && "$huella_auditada" != "${HUELLAS_SECRETOS_LOCALES[$rol_auditado]}" ]]; then
      echo "❌ $nombre: el secreto remoto '$rol_auditado' no coincide con el material local." >&2
      echo "   No se ha modificado ni detenido ningún contenedor. La rotación requiere un procedimiento coordinado." >&2
      exit 1
    fi
    if [[ "$huella_auditada" != "missing" ]]; then
      COPIAS_SECRETOS_REMOTAS["$rol_auditado"]=$((
        COPIAS_SECRETOS_REMOTAS[$rol_auditado] + 1
      ))
    fi
  done <<< "$resultado_auditoria"
  [[ "$vistos_vrrp" == 1 && "$vistos_session" == 1 \
      && "$vistos_cluster" == 1 ]] || {
    echo "❌ $nombre: auditoría remota de secretos incompleta." >&2
    exit 1
  }
  echo "  · $nombre: secretos sin divergencias"
done

if [[ -z "$FRESH_INSTALL" ]]; then
  for rol_auditado in vrrp session cluster; do
    (( COPIAS_SECRETOS_REMOTAS[$rol_auditado] >= 1 )) || {
      echo "❌ No queda ninguna copia remota acreditada del secreto '$rol_auditado'." >&2
      echo "   No se sustituirá por material local sin un procedimiento explícito de recuperación o rotación." >&2
      exit 1
    }
  done
fi

TX_MODE=v2
for entrada in "${NODOS[@]}"; do
  nombre_revision="${entrada%%:*}"
  [[ "${PROTOCOLO_ACTUAL[$nombre_revision]}" == v2 ]] || TX_MODE=legacy
done

echo "· auditando interfaz, identidad IP y puerto de cada host"
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip iface prio clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH_TOPOLOGIA
  puerto_detectado="$("${SSH_TOPOLOGIA[@]}" \
    "grep -oE 'Target=.FIP_PUERTO.[^>]*>[0-9]+' '$PLANTILLA' 2>/dev/null | grep -oE '[0-9]+$' | tail -1" \
    || true)"
  puerto_detectado="${puerto_detectado:-$PUERTO_POR_OMISION}"
  if ! entero_decimal_canonico "$puerto_detectado" \
      || (( 10#$puerto_detectado < 1 || 10#$puerto_detectado > 65535 )); then
      echo "❌ $nombre: la plantilla conserva un puerto no válido." >&2
      exit 1
  fi
  case " $PUERTOS_VETADOS " in
    *" $puerto_detectado "*)
      echo "❌ $nombre: la plantilla conserva el puerto vetado $puerto_detectado." >&2
      exit 1 ;;
  esac
  PUERTO_POR_NODO_REAL["$nombre"]="$puerto_detectado"
  "${SSH_TOPOLOGIA[@]}" "
set -eu
ip link show dev '$iface' >/dev/null
ip -o -4 addr show | awk -v objetivo='$ip' '
  { split(\$4, partes, \"/\") }
  partes[1] == objetivo { encontrada=1 }
  END { exit !encontrada }
'"
  echo "  · $nombre: $ip en $iface, panel $puerto_detectado"
done

echo "· validando offline los estados de todos los nodos antes de cualquier parada"
PREFLIGHT_STATE_DIR="$(umask 077; mktemp -d "${TMPDIR:-/tmp}/floating-ip-preflight.XXXXXX")"
chmod 0700 "$PREFLIGHT_STATE_DIR"
umask 077
POOL_SEED_TMP=""
RESULTADO_PREFLIGHT=""
# shellcheck disable=SC2329  # invocada indirectamente por trap(1)
limpiar_temporales_locales() {
  [[ -z "$POOL_SEED_TMP" ]] || rm -f -- "$POOL_SEED_TMP"
  [[ -z "$RESULTADO_PREFLIGHT" ]] || rm -f -- "$RESULTADO_PREFLIGHT"
  if [[ -n "${PREFLIGHT_STATE_DIR:-}" && -d "$PREFLIGHT_STATE_DIR" \
      && ! -L "$PREFLIGHT_STATE_DIR" ]]; then
    find "$PREFLIGHT_STATE_DIR" -mindepth 1 -maxdepth 1 -type f \
      -exec rm -f -- {} +
    rmdir -- "$PREFLIGHT_STATE_DIR" 2>/dev/null || true
  fi
}
# shellcheck disable=SC2329  # invocada indirectamente por trap(1)
finalizar_despliegue() {
  local estado="$?" recuperacion=0
  trap - EXIT HUP INT TERM
  if [[ -n "${TX_ACTIVA:-}" && -z "${TX_EN_RECOVERY:-}" ]]; then
    set +e
    recuperar_transaccion_cluster
    recuperacion=$?
    set -e
    (( recuperacion == 0 )) || estado=1
  fi
  limpiar_temporales_locales
  exit "$estado"
}
trap finalizar_despliegue EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
OBSERVACIONES_TSV="$PREFLIGHT_STATE_DIR/observations.tsv"
: > "$OBSERVACIONES_TSV"
chmod 0600 "$OBSERVACIONES_TSV"
# Se reutilizan en la fase transaccional para detectar escrituras entre el
# snapshot de sólo lectura y la parada de cada contenedor.
# shellcheck disable=SC2034
declare -A HUELLA_POOL_REMOTA=()
# shellcheck disable=SC2034
declare -A HUELLA_SEGURIDAD_REMOTA=()
observador_estado_serializado="$(declare -f observar_estado_remoto)"
descargador_estado_serializado="$(declare -f descargar_estado_remoto)"
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip iface prio clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH_ESTADO
  pool_local="-"
  seguridad_local="-"
  for recurso in pool security; do
    fichero_remoto="$recurso.json"
    metadato="$("${SSH_ESTADO[@]}" \
      "set -euo pipefail; $observador_estado_serializado; observar_estado_remoto \
        '$DIR_BOOT' '$fichero_remoto'")" || {
      echo "❌ $nombre: no se pudo observar $fichero_remoto de forma segura." >&2
      exit 1
    }
    if [[ "$metadato" == absent ]]; then
      huella_remota="absent"
    elif [[ "$metadato" =~ ^present\;([0-9a-f]{64})\;([0-9]+)$ ]]; then
      huella_remota="${BASH_REMATCH[1]}"
      bytes_remotos="${BASH_REMATCH[2]}"
      fichero_local="$PREFLIGHT_STATE_DIR/$nombre.$fichero_remoto"
      umask 077
      "${SSH_ESTADO[@]}" \
        "set -euo pipefail; $descargador_estado_serializado; descargar_estado_remoto \
          '$DIR_BOOT' '$fichero_remoto' '$huella_remota' '$bytes_remotos'" \
        > "$fichero_local" || {
        rm -f -- "$fichero_local"
        echo "❌ $nombre: $fichero_remoto cambió durante el preflight." >&2
        exit 1
      }
      chmod 0600 "$fichero_local"
      huella_local="$(sha256sum -- "$fichero_local")"
      huella_local="${huella_local%% *}"
      [[ "$huella_local" == "$huella_remota" \
          && "$(stat -c %s -- "$fichero_local")" == "$bytes_remotos" ]] || {
        echo "❌ $nombre: la copia local de $fichero_remoto no conserva su huella." >&2
        exit 1
      }
      if [[ "$recurso" == pool ]]; then
        pool_local="$(basename -- "$fichero_local")"
      else
        seguridad_local="$(basename -- "$fichero_local")"
      fi
    else
      echo "❌ $nombre: metadatos no válidos para $fichero_remoto." >&2
      exit 1
    fi
    if [[ "$recurso" == pool ]]; then
      # shellcheck disable=SC2034  # consumida por la fase transaccional
      HUELLA_POOL_REMOTA["$nombre"]="$huella_remota"
    else
      # shellcheck disable=SC2034  # consumida por la fase transaccional
      HUELLA_SEGURIDAD_REMOTA["$nombre"]="$huella_remota"
    fi
  done
  printf '%s\t%s\t%s\n' "$nombre" "$pool_local" "$seguridad_local" \
    >> "$OBSERVACIONES_TSV"
done

MANIFIESTO_PREFLIGHT="$PREFLIGHT_STATE_DIR/manifest.json"
python3 - "$OBSERVACIONES_TSV" "$MANIFIESTO_PREFLIGHT" \
    "${NODOS[@]}" <<'PY'
import json
import os
import sys

tsv, destino, *entradas = sys.argv[1:]
partes = [entrada.split(":", 2) for entrada in entradas]
topologia = [entrada[0] for entrada in partes]
ips_gestion = [entrada[1] for entrada in partes]
observaciones = []
with open(tsv, "r", encoding="utf-8") as origen:
    for linea in origen:
        nodo, pool, seguridad = linea.rstrip("\n").split("\t")
        observaciones.append({
            "node": nodo,
            "pool": None if pool == "-" else pool,
            "security": None if seguridad == "-" else seguridad,
        })
temporal = destino + ".tmp"
with open(temporal, "x", encoding="utf-8") as salida:
    json.dump({
        "schema": 1,
        "topology": topologia,
        "writer": topologia[0],
        "management_ips": ips_gestion,
        "observations": observaciones,
    }, salida, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    salida.write("\n")
    salida.flush()
    os.fsync(salida.fileno())
os.chmod(temporal, 0o600)
os.replace(temporal, destino)
PY
chmod 0600 "$MANIFIESTO_PREFLIGHT"
RESULTADO_PREFLIGHT="$(umask 077; mktemp "${TMPDIR:-/tmp}/floating-ip-result.XXXXXX")"

if [[ -n "$FRESH_INSTALL" ]]; then
  POOL_SEED_TMP="$(umask 077; mktemp "${TMPDIR:-/tmp}/floating-ip-pool.XXXXXX")"
  POOL_SEED_TIMESTAMP="$(python3 - <<'PY'
from datetime import datetime, timezone

print(datetime.now(timezone.utc).isoformat(timespec="seconds"))
PY
)"
  generar_semilla_pool "$POOL_SEED_TIMESTAMP" "$DHCP_DESDE" \
    "${DIRECCIONES[@]}" > "$POOL_SEED_TMP"
  chmod 0600 "$POOL_SEED_TMP"
  PYTHONPATH="$REPO_ROOT/docker/keepalived/panel" \
    python3 - "$POOL_SEED_TMP" <<'PY'
import json
import os
import sys
from datetime import datetime

import pool

with open(sys.argv[1], "r", encoding="utf-8") as archivo:
    semilla = json.load(archivo)
if "revision" in semilla:
    raise SystemExit("La semilla inicial debe conservar el formato legacy")
if not semilla.get("direcciones"):
    raise SystemExit("La semilla inicial del pool no puede estar vacía")
for campo in (semilla.get("actualizado"),
              *(d.get("creada") for d in semilla["direcciones"])):
    marca = datetime.fromisoformat(campo)
    if marca.tzinfo is None:
        raise SystemExit("La semilla contiene una marca temporal sin zona horaria")
problemas = pool.validar(semilla)
if problemas:
    raise SystemExit("Semilla inicial del pool no válida: " + "; ".join(problemas))
# Esta API pública normaliza el legacy y aplica el límite canónico del runtime.
pool.Pool.huella(semilla)
if os.path.getsize(sys.argv[1]) > 512 * 1024:
    raise SystemExit("La semilla persistida supera el máximo seguro de 512 KiB")
PY
  POOL_SEED_SHA256="$(sha256sum "$POOL_SEED_TMP")"
  POOL_SEED_SHA256="${POOL_SEED_SHA256%% *}"
  [[ "$POOL_SEED_SHA256" =~ ^[0-9a-f]{64}$ ]]
fi

echo "· comprobando imagen y almacenamiento antes de recrear contenedores"
declare -A IMAGEN_ID_ESPERADA=()
declare -A IMAGEN_REFERENCIA_INMUTABLE=()
declare -A REVISIONES_CANDIDATAS=()
# El validador causal se ejecuta dentro de la propia imagen Linux. Así el host
# de administración sólo necesita Python estándar y no una copia accidental de
# las dependencias criptográficas del producto. La cohorte real ya fue fijada a
# N/N, por lo que todos los nodos deben resolver la misma revisión candidata.
CANDIDATOS_PREFLIGHT=("${NODOS[@]}")
IMAGEN_ID_VALIDADORA=""
IP_VALIDADOR=""
CLAVE_VALIDADOR=""
for entrada in "${CANDIDATOS_PREFLIGHT[@]}"; do
  IFS=: read -r nombre ip iface prio clave <<< "$entrada"
  imagen="$(imagen_para "$nombre")"
  ssh_para "$clave" "$ip" SSH_PREFLIGHT
  echo "  · $nombre: $imagen"
  metadatos_imagen="$("${SSH_PREFLIGHT[@]}" \
    "set -eu
docker pull -q '$imagen' >/dev/null
imagen_id=\$(docker image inspect --format '{{.Id}}' '$imagen')
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \"\$imagen_id\" \
  | grep -Fx -- '$imagen' >/dev/null
docker image inspect --format '{{.Id}}|{{index .Config.Labels \"org.opencontainers.image.revision\"}}|{{index .Config.Labels \"org.opencontainers.image.version\"}}|{{index .Config.Labels \"io.ezr43l.cluster-protocol\"}}' \"\$imagen_id\"")"
  IFS='|' read -r imagen_id revision_imagen version_imagen protocolo_imagen \
    <<< "$metadatos_imagen"
  [[ "$imagen_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "❌ $nombre: Docker no devolvió un ID inmutable para $imagen." >&2
    exit 1
  }
  [[ "$revision_imagen" =~ ^[0-9a-f]{12,64}$ \
      && "$version_imagen" == "$APP_VERSION" && "$protocolo_imagen" == "v2" ]] || {
    echo "❌ $nombre: la imagen no acredita revisión, versión y protocolo del candidato." >&2
    exit 1
  }
  IMAGEN_ID_ESPERADA["$nombre"]="$imagen_id"
  IMAGEN_REFERENCIA_INMUTABLE["$nombre"]="$imagen"
  REVISIONES_CANDIDATAS["$revision_imagen"]=1
  if [[ "$nombre" == "$ESCRITOR_ESPERADO" ]]; then
    IMAGEN_ID_VALIDADORA="$imagen_id"
    IP_VALIDADOR="$ip"
    CLAVE_VALIDADOR="$clave"
  fi
done
(( ${#REVISIONES_CANDIDATAS[@]} == 1 )) || {
  echo "❌ Los nodos resolvieron revisiones de código distintas para la misma release." >&2
  exit 1
}
[[ -n "$IMAGEN_ID_VALIDADORA" && -n "$IP_VALIDADOR" \
    && -n "$CLAVE_VALIDADOR" ]] || {
  echo "❌ No se pudo resolver una imagen candidata en el escritor lógico." >&2
  exit 1
}
ssh_para "$CLAVE_VALIDADOR" "$IP_VALIDADOR" SSH_VALIDADOR
argumento_fresh_contenedor=""
[[ -z "$FRESH_INSTALL" ]] || argumento_fresh_contenedor=" --allow-fresh-empty"
if tar -C "$PREFLIGHT_STATE_DIR" -cf - . | "${SSH_VALIDADOR[@]}" "
set -euo pipefail
docker run --rm -i \
  --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=64 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
  --entrypoint /bin/sh '$IMAGEN_ID_VALIDADORA' -c '
set -eu
umask 077
mkdir -m 0700 /tmp/preflight
tar -o -xf - -C /tmp/preflight
find /tmp/preflight -type d -exec chmod 0700 {} +
find /tmp/preflight -type f -exec chmod 0600 {} +
exec python3 /opt/panel/preflight_remoto.py \
  --manifest /tmp/preflight/manifest.json$argumento_fresh_contenedor
'" > "$RESULTADO_PREFLIGHT"; then
  chmod 0600 "$RESULTADO_PREFLIGHT"
else
  codigo_preflight="$(python3 - "$RESULTADO_PREFLIGHT" <<'PY'
import json
import sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8"))["error"]["code"])
except Exception:
    print("PREFLIGHT_UNKNOWN")
PY
)"
  echo "❌ El estado persistente no supera el preflight causal: $codigo_preflight" >&2
  exit 1
fi
python3 - "$RESULTADO_PREFLIGHT" <<'PY'
import json
import sys
resultado = json.load(open(sys.argv[1], encoding="utf-8"))
if resultado.get("ok") is not True:
    raise SystemExit("el validador no devolvió ok=true")
PY
if [[ -n "$FRESH_INSTALL" ]]; then
  echo "  · pool y seguridad están ausentes en todo el clúster fresco"
else
  echo "  · pool y seguridad tienen un estado dominante recuperable"
fi

# Sólo después de acreditar el estado con el mismo código de la release se
# permite normalizar el almacenamiento de los nodos que serán recreados.

# Se renderizan primero todos los artefactos locales. Todavía no se toca ningún
# host; un error de plantilla no puede dejar una cohorte a medias.
declare -A PLANTILLA_LOCAL=() CID_CANDIDATO=()
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre _ _ _ _ <<< "$entrada"
  puerto="${PUERTO_POR_NODO_REAL[$nombre]}"
  pares="$(pares_de "$nombre" "$puerto")"
  imagen_inmutable="${IMAGEN_REFERENCIA_INMUTABLE[$nombre]}"
  plantilla_local="$PREFLIGHT_STATE_DIR/template.$nombre.xml"
  python3 "$RENDERER" unraid/my-Keepalived.xml \
      --repository "$imagen_inmutable" \
      --webui "http://[IP]:$puerto/" \
      --set "FIP_PUERTO=$puerto" --set "/datos=$DIR_BOOT" \
      --set "FIP_NODO=$nombre" --set "FIP_PARES=$pares" \
      --set "FIP_NODOS=$TABLA" --set "FIP_VIP_PREFIX=$VIP_PREFIJO" \
      --set "FIP_RETARDO=$PREEMPT_DELAY" \
      --set "/run/secrets/fip_vrrp_auth=$REMOTE_SECRETS_DIR/vrrp-auth.txt" \
      --set "FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth" \
      --set "/run/secrets/fip_session_secret=$REMOTE_SECRETS_DIR/session-secret.txt" \
      --set "FIP_SESSION_SECRET_FILE=/run/secrets/fip_session_secret" \
      --set "/run/secrets/fip_cluster_token=$REMOTE_SECRETS_DIR/cluster-token.txt" \
      --set "FIP_CLUSTER_TOKEN_FILE=/run/secrets/fip_cluster_token" \
    | sed -E "s#https://raw.githubusercontent.com/Ezr43l/(floating-ip-s|keepalived-s)/[^/]+/logo/icono.png#$ICONO_URL#g" \
      > "$plantilla_local"
  chmod 0600 -- "$plantilla_local"
  [[ -s "$plantilla_local" && "$(stat -c %s -- "$plantilla_local")" -le 1048576 ]]
  PLANTILLA_LOCAL["$nombre"]="$plantilla_local"
done

revalidar_cas_cluster() {
  local entrada nombre ip clave recurso fichero metadato huella respuesta linea rol valor
  local contenedor_auditado="${1:-$CONTENEDOR}"
  local -a SSH_CAS=()
  local observador auditor
  observador="$(declare -f observar_estado_remoto)"
  auditor="$(declare -f auditar_secretos_remotos)"
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nombre ip _ _ clave <<< "$entrada"
    ssh_para "$clave" "$ip" SSH_CAS
    for recurso in pool security; do
      fichero="$recurso.json"
      metadato="$("${SSH_CAS[@]}" \
        "set -euo pipefail; $observador; observar_estado_remoto '$DIR_BOOT' '$fichero'")" \
        || return 1
      if [[ "$metadato" == absent ]]; then
        huella=absent
      elif [[ "$metadato" =~ ^present\;([0-9a-f]{64})\;[0-9]+$ ]]; then
        huella="${BASH_REMATCH[1]}"
      else
        return 1
      fi
      if [[ "$recurso" == pool ]]; then
        [[ "$huella" == "${HUELLA_POOL_REMOTA[$nombre]}" ]] || return 1
      else
        [[ "$huella" == "${HUELLA_SEGURIDAD_REMOTA[$nombre]}" ]] || return 1
      fi
    done
    respuesta="$("${SSH_CAS[@]}" \
      "set -euo pipefail; $auditor; auditar_secretos_remotos '$REMOTE_SECRETS_DIR' '$contenedor_auditado'")" \
      || return 1
    vistos_vrrp=0; vistos_session=0; vistos_cluster=0
    while IFS= read -r linea; do
      [[ "$linea" =~ ^(vrrp|session|cluster)=(missing|[0-9a-f]{64})$ ]] || return 1
      rol="${BASH_REMATCH[1]}"; valor="${BASH_REMATCH[2]}"
      [[ "$valor" == "${HUELLA_SECRETO_REMOTA[$nombre:$rol]}" ]] || return 1
      printf -v "vistos_$rol" '%s' 1
    done <<< "$respuesta"
    [[ "$vistos_vrrp" == 1 && "$vistos_session" == 1 && "$vistos_cluster" == 1 ]] \
      || return 1
  done
}

TXID="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$TXID" =~ ^[0-9a-f]{32}$ ]]
ROLLBACK_CONTENEDOR="fip-rb-$TXID"
echo "· abriendo la transacción N/N ($TX_MODE)"
# Se arma el trap antes de la primera llamada: una desconexión puede ocultar que
# el begin remoto sí llegó a publicarse, incluso si SSH devuelve error local.
TX_ACTIVA="$TXID"
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_begin "$TX_ROOT" "$TXID"
done
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_prepare_paths \
    "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  tx_remoto "$clave" "$ip" fip_tx_set_mode "$TX_ROOT" "$TXID" "$TX_MODE"
done

if [[ "$TX_MODE" == legacy ]]; then
  # Este snapshot preliminar nunca se restaura si la barrera N/N queda parcial.
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r _ ip _ _ clave <<< "$entrada"
    tx_preparar_almacen_remoto "$clave" "$ip" "$TXID"
    tx_remoto "$clave" "$ip" fip_tx_snapshot \
      "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  done
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r _ ip _ _ clave <<< "$entrada"
    tx_remoto "$clave" "$ip" fip_tx_install_freeze \
      "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  done
else
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r _ ip _ _ clave <<< "$entrada"
    tx_remoto "$clave" "$ip" fip_tx_install_freeze \
      "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
    tx_preparar_almacen_remoto "$clave" "$ip" "$TXID"
  done
  revalidar_cas_cluster || {
    echo "❌ El estado o los secretos cambiaron después del freeze v2." >&2
    exit 1
  }
  # Una petición que ya había superado su guard antes de publicar el marker
  # puede terminar todavía. Exigimos una segunda observación estable tras una
  # ventana corta antes de considerar autoritativo el snapshot v2.
  sleep 2
  revalidar_cas_cluster || {
    echo "❌ Una mutación en vuelo terminó durante el drenaje del freeze v2." >&2
    exit 1
  }
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r _ ip _ _ clave <<< "$entrada"
    tx_remoto "$clave" "$ip" fip_tx_snapshot \
      "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  done
fi

# Primera barrera destructiva: TERM y rename, sin borrar el contenedor previo.
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  revalidar_cas_cluster || {
    echo "❌ El estado o los secretos cambiaron justo antes de una parada." >&2
    exit 1
  }
  tx_remoto "$clave" "$ip" fip_tx_preserve_container \
    "$TX_ROOT" "$TXID" "$CONTENEDOR" "$ROLLBACK_CONTENEDOR"
done
if [[ "$TX_MODE" == legacy ]]; then
  revalidar_cas_cluster "$ROLLBACK_CONTENEDOR" || {
    echo "❌ El estado o los secretos cambiaron durante el drenaje legacy." >&2
    exit 1
  }
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r _ ip _ _ clave <<< "$entrada"
    tx_remoto "$clave" "$ip" fip_tx_snapshot_quiesced \
      "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  done
fi

# Con el baseline global durable se permiten configuración, secretos, bootstrap
# y staging. La plantilla real no se publica hasta la decisión commit.
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip iface _ clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH
  puerto="${PUERTO_POR_NODO_REAL[$nombre]}"
  pares="$(pares_de "$nombre" "$puerto")"
  imagen_id="${IMAGEN_ID_ESPERADA[$nombre]}"
  icono="$ICONO_URL"

  extractor_vips="$(declare -f extraer_vips_config)"
  limpieza=""
  for e in "${DIRECCIONES[@]}"; do
    IFS=: read -r _ vip _ _ _ _ <<< "$e"
    limpieza="$limpieza ip addr del $vip/$VIP_PREFIJO dev $iface >/dev/null 2>&1 || true;"
  done
  "${SSH[@]}" "set -euo pipefail
$extractor_vips
ips_pool=\$(extraer_vips_config '$CONF' '$VIP_PREFIJO' '$iface')
for vip_pool in \$ips_pool; do
  ip addr del \$vip_pool/$VIP_PREFIJO dev $iface >/dev/null 2>&1 || true
done
$limpieza"

  # El contenido secreto viaja sólo por stdin; nunca forma parte del comando ni
  # del journal. El instalador no rota un fichero ya existente.
  instalador_secretos="$(declare -f instalar_secretos_remotos)"
  {
    printf '%s\n' "$VRRP_AUTH_PASS" "$SESSION_SECRET" "$CLUSTER_TOKEN"
  } | "${SSH[@]}" \
    "set -euo pipefail; $instalador_secretos; instalar_secretos_remotos '$REMOTE_SECRETS_DIR'"

  if [[ -n "$FRESH_INSTALL" ]]; then
    marcadores_serializados="$(declare -f instalar_marcadores_bootstrap)"
    "${SSH[@]}" \
      "set -euo pipefail; $marcadores_serializados; instalar_marcadores_bootstrap '$DIR_BOOT'"
    instalador_pool="$(declare -f instalar_semilla_pool)"
    cat "$POOL_SEED_TMP" | "${SSH[@]}" \
      "set -euo pipefail; $instalador_pool; instalar_semilla_pool '$DIR_BOOT' '$POOL_SEED_SHA256'"
  fi

  escritor_config="$(declare -f escribir_configuracion_atomica)"
  config_for "$iface" "$nombre" | "${SSH[@]}" \
    "set -euo pipefail; $escritor_config; escribir_configuracion_atomica '$DIR_BOOT' '$CONF'"
  "${SSH[@]}" "set -euo pipefail; mkdir -p -- '$PLANTILLAS'; \
    test -d '$PLANTILLAS'; test ! -L '$PLANTILLAS'; \
    test \"\$(readlink -f -- '$PLANTILLAS')\" = '$PLANTILLAS'"
  tx_stage_template_remoto "$clave" "$ip" "$TXID" "${PLANTILLA_LOCAL[$nombre]}"

  cid="$("${SSH[@]}" "set -euo pipefail
docker run -d --name '$CONTENEDOR' \
  --restart=unless-stopped --init --read-only \
  --net=host --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=NET_BROADCAST --cap-add=NET_RAW --cap-add=SETGID \
  --security-opt=no-new-privileges --pids-limit=256 \
  -v '$REMOTE_SECRETS_DIR/vrrp-auth.txt:/run/secrets/fip_vrrp_auth:ro' \
  -v '$REMOTE_SECRETS_DIR/session-secret.txt:/run/secrets/fip_session_secret:ro' \
  -v '$REMOTE_SECRETS_DIR/cluster-token.txt:/run/secrets/fip_cluster_token:ro' \
  -e FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth \
  -e FIP_SESSION_SECRET_FILE=/run/secrets/fip_session_secret \
  -e FIP_CLUSTER_TOKEN_FILE=/run/secrets/fip_cluster_token \
  -e FIP_SESSION_HOURS=12 -e FIP_COOKIE_SECURE=0 -e FIP_TOTP_ISSUER=Keepalived \
  --tmpfs /run:rw,nosuid,noexec,size=32m --tmpfs /tmp:rw,nosuid,noexec,size=32m \
  -v '$DIR_BOOT:/datos' -e FIP_NODO='$nombre' -e FIP_PARES='$pares' \
  -e FIP_NODOS='$TABLA' -e FIP_PUERTO='$puerto' -e FIP_DATOS=/datos \
  -e FIP_CONF=/datos/keepalived.conf -e FIP_VIP_PREFIX='$VIP_PREFIJO' \
  -e FIP_RETARDO='$PREEMPT_DELAY' \
  --label io.ezr43l.deploy-transaction='$TXID' \
  --label io.ezr43l.deploy-role=candidate \
  --label io.ezr43l.deploy-image-digest='$IMAGE_DIGEST' \
  --label net.unraid.docker.managed=dockerman \
  --label 'net.unraid.docker.webui=http://[IP]:$puerto/' \
  --label net.unraid.docker.icon='$icono' \
  '$imagen_id'")"
  [[ "$cid" =~ ^[0-9a-f]{64}$ ]] || {
    echo "❌ $nombre no devolvió un CID candidato válido." >&2
    exit 1
  }
  CID_CANDIDATO["$nombre"]="$cid"
  tx_remoto "$clave" "$ip" fip_tx_record_candidate \
    "$TX_ROOT" "$TXID" "$CONTENEDOR" "$cid"
done

echo
echo "· esperando readiness real y elección de portadores"

# ─────────────────────────────────────────────────────────────────────────────
# La puerta final comprueba el panel y la propiedad de cada dirección antes de
# declarar terminado el despliegue.
# ─────────────────────────────────────────────────────────────────────────────
fallos=0
declare -A HUELLAS_POOL_CANDIDATOS=()
declare -A HUELLAS_SEGURIDAD_CANDIDATOS=()

for entrada in "${SELECCION[@]}"; do
  IFS=: read -r nombre ip iface prio clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH
  imagen_id_esperada="${IMAGEN_ID_ESPERADA[$nombre]}"
  cid_esperado="${CID_CANDIDATO[$nombre]}"
  puerto="${PUERTO_POR_NODO_REAL[$nombre]}"
  tx_remoto "$clave" "$ip" fip_tx_install_freeze \
    "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
  printf '  %-8s candidato ' "$nombre"
  candidato=""
  for _ in $(seq 1 20); do
    salud="$(curl -sf --max-time 5 --max-filesize 4096 \
      "http://$ip:$puerto/api/health" 2>/dev/null)" || salud=""
    if printf '%s' "$salud" | python3 -c '
import json, sys
esperada = sys.argv[1]
objeto = json.load(sys.stdin)
assert objeto.get("estado") == "ok"
assert objeto.get("version") == {"version": esperada}
' "$APP_VERSION" >/dev/null 2>&1; then
      candidato="$("${SSH[@]}" "
set -euo pipefail
[ \"\$(docker inspect --format '{{.State.Running}}' '$CONTENEDOR')\" = true ]
[ \"\$(docker inspect --format '{{.Id}}' '$CONTENEDOR')\" = '$cid_esperado' ]
[ \"\$(docker inspect --format '{{.Image}}' '$CONTENEDOR')\" = '$imagen_id_esperada' ]
[ \"\$(docker inspect --format '{{index .Config.Labels \"io.ezr43l.deploy-transaction\"}}' '$CONTENEDOR')\" = '$TXID' ]
[ \"\$(docker inspect --format '{{index .Config.Labels \"io.ezr43l.deploy-role\"}}' '$CONTENEDOR')\" = candidate ]
[ \"\$(docker inspect --format '{{index .Config.Labels \"io.ezr43l.deploy-image-digest\"}}' '$CONTENEDOR')\" = '$IMAGE_DIGEST' ]
procesos=\$(docker top '$CONTENEDOR' -eo comm)
printf '%s\\n' \"\$procesos\" | grep -Fxq python3
printf '%s\\n' \"\$procesos\" | grep -Fxq keepalived
for marcador in .bootstrap-pool .bootstrap-security; do
  [ ! -e '$DIR_BOOT'/\$marcador ] && [ ! -L '$DIR_BOOT'/\$marcador ]
done
for estado in pool.json security.json; do
  ruta='$DIR_BOOT'/\$estado
  [ -f \"\$ruta\" ] && [ ! -L \"\$ruta\" ] \
    && [ \$(stat -c %h \"\$ruta\") = 1 ] \
    && [ \$(stat -c %u:%g:%a \"\$ruta\") = 0:0:600 ]
done
pool_sha=\$(sha256sum '$DIR_BOOT/pool.json'); pool_sha=\${pool_sha%% *}
security_sha=\$(sha256sum '$DIR_BOOT/security.json'); security_sha=\${security_sha%% *}
printf '%s %s\\n' \"\$pool_sha\" \"\$security_sha\"
" 2>/dev/null)" || candidato=""
      [[ "$candidato" =~ ^[0-9a-f]{64}[[:space:]][0-9a-f]{64}$ ]] && break
      candidato=""
    fi
    sleep 3
  done
  if [[ -n "$candidato" ]]; then
    pool_candidato="${candidato%% *}"
    seguridad_candidato="${candidato##* }"
    HUELLAS_POOL_CANDIDATOS["$pool_candidato"]=1
    HUELLAS_SEGURIDAD_CANDIDATOS["$seguridad_candidato"]=1
    echo "✅ panel + pool + seguridad + Keepalived"
  else
    echo "❌ no alcanzó readiness completa en http://$ip:$puerto/" >&2
    fallos=1
  fi
done

# Los tres secretos activos se vuelven a acreditar en todos los nodos justo
# antes de verified. Un mount o fichero cambiado después del preflight impide
# decidir commit aunque panel/pool parezcan sanos.
auditor_secretos_final="$(declare -f auditar_secretos_remotos)"
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip _ _ clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH_SECRETOS_FINAL
  respuesta_secretos="$("${SSH_SECRETOS_FINAL[@]}" \
    "set -euo pipefail; $auditor_secretos_final; auditar_secretos_remotos \
      '$REMOTE_SECRETS_DIR' '$CONTENEDOR'" 2>/dev/null)" || respuesta_secretos=""
  vistos_vrrp=0; vistos_session=0; vistos_cluster=0
  while IFS= read -r linea; do
    [[ "$linea" =~ ^(vrrp|session|cluster)=([0-9a-f]{64})$ ]] || continue
    rol="${BASH_REMATCH[1]}"; valor="${BASH_REMATCH[2]}"
    [[ "$valor" == "${HUELLAS_SECRETOS_LOCALES[$rol]}" ]] || continue
    printf -v "vistos_$rol" '%s' 1
  done <<< "$respuesta_secretos"
  if [[ "$vistos_vrrp" != 1 || "$vistos_session" != 1 || "$vistos_cluster" != 1 ]]; then
    echo "❌ $nombre no conserva los tres secretos activos acreditados." >&2
    fallos=1
  fi
done

if (( ${#HUELLAS_POOL_CANDIDATOS[@]} != 1 )); then
  echo "❌ Los candidatos no conservan un único snapshot de pool." >&2
  fallos=1
fi
if (( ${#HUELLAS_SEGURIDAD_CANDIDATOS[@]} != 1 )); then
  echo "❌ Los candidatos no conservan un único snapshot de seguridad." >&2
  fallos=1
fi

echo
for e in "${DIRECCIONES[@]}"; do
  IFS=: read -r nombre vip vrid puerto ruta preferente <<< "$e"
  portadores=()
  auditoria_vip_completa=1
  for entrada in "${NODOS[@]}"; do
    IFS=: read -r nnombre ip iface prio clave <<< "$entrada"
    ssh_para "$clave" "$ip" SSH_VIP
    if "${SSH_VIP[@]}" \
        "ip -o -4 addr show dev '$iface' | awk -v objetivo='$vip/$VIP_PREFIJO' '\$4 == objetivo { encontrada=1 } END { exit !encontrada }'" \
        2>/dev/null; then
      portadores+=("$nnombre")
    else
      estado_ssh=$?
      if (( estado_ssh != 1 )); then
        echo "❌ $nombre: no se pudo auditar $vip en el nodo $nnombre." >&2
        auditoria_vip_completa=0
        fallos=1
      fi
    fi
  done
  if (( auditoria_vip_completa == 0 )); then
    continue
  elif (( ${#portadores[@]} == 0 )); then
    echo "❌ $nombre: nadie ha tomado $vip. Revisa: docker logs $CONTENEDOR" >&2
    fallos=1
  elif (( ${#portadores[@]} > 1 )); then
    echo "❌ $nombre: split-brain; $vip está simultáneamente en ${portadores[*]}." >&2
    fallos=1
  elif curl -sf --max-time 6 "http://$vip:$puerto$ruta" >/dev/null 2>&1; then
    echo "  ✅ $nombre responde en http://$vip:$puerto$ruta (ahora en ${portadores[0]})"
  else
    echo "⚠ $nombre: $vip está asignada en ${portadores[0]}, pero el servicio no contesta ahí." >&2
    fallos=1
  fi
done

if (( fallos != 0 )); then
  echo "❌ Las puertas finales fallaron; se ejecutará rollback N/N." >&2
  exit 1
fi

echo "· publicando la decisión commit tras verified N/N"
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_mark_verified "$TX_ROOT" "$TXID"
done

# El escritor conserva la evidencia autoritativa. Decide primero y su journal
# se limpia el último, después de propagar la decisión a todos los peers.
entrada_escritor="${NODOS[0]}"
IFS=: read -r _ ip_escritor _ _ clave_escritor <<< "$entrada_escritor"
tx_remoto "$clave_escritor" "$ip_escritor" fip_tx_decide_commit "$TX_ROOT" "$TXID"
for entrada in "${NODOS[@]:1}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_decide_commit "$TX_ROOT" "$TXID"
done
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_install_template \
    "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
done
for entrada in "${NODOS[@]}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_mark_committed \
    "$TX_ROOT" "$TXID" "$DIR_BOOT" "$PLANTILLA"
done
for entrada in "${NODOS[@]:1}"; do
  IFS=: read -r _ ip _ _ clave <<< "$entrada"
  tx_remoto "$clave" "$ip" fip_tx_cleanup "$TX_ROOT" "$TXID"
done
tx_remoto "$clave_escritor" "$ip_escritor" fip_tx_cleanup "$TX_ROOT" "$TXID"
TX_ACTIVA=""

# Los caches de icono no participan en la corrección del clúster y se actualizan
# sólo tras commit, para que un fallo cosmético nunca fuerce rollback de datos.
for entrada in "${NODOS[@]}"; do
  IFS=: read -r nombre ip _ _ clave <<< "$entrada"
  ssh_para "$clave" "$ip" SSH_ICONO
  puerto="${PUERTO_POR_NODO_REAL[$nombre]}"
  "${SSH_ICONO[@]}" "set -euo pipefail
icon_tmp=\$(mktemp /tmp/Keepalived-icon.XXXXXX)
trap 'rm -f -- \"\$icon_tmp\"' EXIT HUP INT TERM
icon_ok=
for intento in \$(seq 1 10); do
  if curl -sf --max-time 5 -o \"\$icon_tmp\" http://127.0.0.1:$puerto/icono.png \
      && [ \"\$(od -An -tx1 -N8 \"\$icon_tmp\" | tr -d ' \n')\" = 89504e470d0a1a0a ]; then
    icon_ok=1; break
  fi
  sleep 3
done
test -n \"\$icon_ok\"
for destino_icono in /var/local/emhttp/plugins/dynamix.docker.manager/images \
    /var/lib/docker/unraid/images; do
  mkdir -p -- \"\$destino_icono\"
  install -m 0644 -- \"\$icon_tmp\" \"\$destino_icono/$CONTENEDOR-icon.png\"
done" 2>/dev/null || echo "  ⚠ $nombre: no se pudo actualizar el icono de Unraid" >&2
done

# Una direccion BORRADA del manifiesto no se limpia sola: la limpieza de arriba
# solo retira lo que el manifiesto declara. Queda huerfana en el interfaz del
# nodo que la sostenia, y hay que quitarla a mano:
#   ip addr del <vip>/<prefijo> dev <iface>
exit 0
