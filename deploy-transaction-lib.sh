#!/usr/bin/env bash
# Libreria de transacciones duraderas para deploy-floating-ip.sh.
#
# No ejecuta un despliegue por si sola. El coordinador debe preparar todos los
# nodos antes de mutar el primero y, durante un rollback de cluster, detener los
# peers antes de restaurar sus snapshots. Ningun fichero del journal se evalua
# como codigo: todos los valores se validan y se leen como datos.

FIP_TX_OWNER_CONTENT='floating-ip-deploy-transaction-v1'
FIP_TX_FREEZE_CONTENT='deploy-freeze-v1'

fip_tx_error() {
  printf 'floating-ip transaction: %s\n' "$*" >&2
  return 1
}

fip_tx_valid_txid() {
  [[ "${1:-}" =~ ^[0-9a-f]{32}$ ]]
}

fip_tx_valid_container_name() {
  [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]
}

fip_tx_valid_cid() {
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

fip_tx_valid_absolute_path() {
  local path="${1:-}"
  [[ "$path" =~ ^/[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ \
      && "$path" != *'/../'* && "$path" != *'/..' \
      && "$path" != *'/./'* && "$path" != *'/.' ]]
}

fip_tx_assert_components() { # <directory path>; missing tail is allowed
  local path="$1" component current=""
  local -a components=()
  fip_tx_valid_absolute_path "$path" \
    || fip_tx_error "ruta absoluta no valida: $path" || return 1
  IFS='/' read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    [[ ! -L "$current" ]] \
      || fip_tx_error "la ruta atraviesa un enlace simbolico: $current" \
      || return 1
    if [[ -e "$current" && ! -d "$current" ]]; then
      fip_tx_error "un componente de la ruta no es directorio: $current"
      return 1
    fi
  done
}

fip_tx_assert_file_parent() { # <file path>
  local path="$1" parent
  fip_tx_valid_absolute_path "$path" \
    || fip_tx_error "ruta de fichero no valida: $path" || return 1
  parent="${path%/*}"
  [[ -n "$parent" ]] || parent=/
  fip_tx_assert_components "$parent"
}

fip_tx_paths_are_disjoint() { # <path a> <path b>
  local a="${1%/}" b="${2%/}"
  [[ "$a" != "$b" && "$a" != "$b/"* && "$b" != "$a/"* ]]
}

fip_tx_validate_paths() { # <data dir> <template file> <transaction root>
  local data="$1" template="$2" root="$3"
  fip_tx_assert_components "$data" || return 1
  fip_tx_assert_file_parent "$template" || return 1
  fip_tx_assert_components "$root" || return 1
  [[ "$data" != /boot && "$data" != /boot/* ]] \
    || fip_tx_error 'el directorio de datos no puede estar bajo /boot' \
    || return 1
  [[ "$root" != / && "$root" != /boot && "$root" != /boot/* ]] \
    || fip_tx_error 'el journal no puede estar en / ni bajo /boot' \
    || return 1
  fip_tx_paths_are_disjoint "$data" "$root" \
    || fip_tx_error 'datos y journal deben ser arboles separados' || return 1
  fip_tx_paths_are_disjoint "$template" "$root" \
    || fip_tx_error 'plantilla y journal deben ser rutas separadas' || return 1
  [[ "$template" != "$data" && "$template" != "$data/"* ]] \
    || fip_tx_error 'la plantilla no puede estar dentro de /datos' || return 1
}

fip_tx_sync_file() {
  sync -f -- "$1" 2>/dev/null || sync
}

fip_tx_sync_dir() {
  sync -f -- "$1" 2>/dev/null || sync
}

fip_tx_regular_root_file() { # <path> <mode> [allow nlink=2]
  local path="$1" mode="$2" allow_two="${3:-}"
  local actual
  [[ "$mode" =~ ^0[0-7]{3}$ ]] && mode="${mode#0}"
  [[ -f "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" ]] \
    || return 1
  actual="$(stat -c '%u:%g:%a:%h' -- "$path")" || return 1
  if [[ -n "$allow_two" ]]; then
    [[ "$actual" == "0:0:$mode:1" || "$actual" == "0:0:$mode:2" ]]
  else
    [[ "$actual" == "0:0:$mode:1" ]]
  fi
}

fip_tx_content_matches() { # <path> <content without trailing newline>
  local path="$1" content="$2" expected actual bytes
  expected="$(printf '%s\n' "$content" | sha256sum)" || return 1
  expected="${expected%% *}"
  actual="$(sha256sum -- "$path")" || return 1
  actual="${actual%% *}"
  bytes="$(wc -c < "$path")" || return 1
  [[ "$actual" == "$expected" && "$bytes" -eq $(( ${#content} + 1 )) ]]
}

fip_tx_atomic_text() { # <target> <mode> <content without trailing newline>
  local target="$1" mode="$2" content="$3" parent tmp
  parent="${target%/*}"; [[ -n "$parent" ]] || parent=/
  tmp="$target.tmp"
  if [[ -e "$target" || -L "$target" ]]; then
    fip_tx_regular_root_file "$target" "$mode" \
      || fip_tx_error "destino de journal inseguro: $target" || return 1
  fi
  if [[ -e "$tmp" || -L "$tmp" ]]; then
    fip_tx_regular_root_file "$tmp" "$mode" \
      || fip_tx_error "temporal de journal inseguro: $tmp" || return 1
    rm -f -- "$tmp" || return 1
  fi
  (umask 077; printf '%s\n' "$content" > "$tmp") || return 1
  chown 0:0 -- "$tmp" || return 1
  chmod "$mode" -- "$tmp" || return 1
  fip_tx_regular_root_file "$tmp" "$mode" || return 1
  fip_tx_sync_file "$tmp" || return 1
  mv -f -- "$tmp" "$target" || return 1
  fip_tx_sync_dir "$parent" || return 1
  fip_tx_regular_root_file "$target" "$mode"
}

fip_tx_open_root() { # <transaction root>
  local root="$1" parent created="" owner_tmp
  fip_tx_assert_components "$root" || return 1
  parent="${root%/*}"; [[ -n "$parent" ]] || parent=/
  if [[ ! -e "$root" && ! -L "$root" ]]; then
    [[ -d "$parent" && ! -L "$parent" ]] \
      || fip_tx_error "no existe el padre real del journal: $parent" || return 1
    (umask 077; mkdir -- "$root") || return 1
    chown 0:0 -- "$root" || return 1
    chmod 0700 -- "$root" || return 1
    created=1
  fi
  [[ -d "$root" && ! -L "$root" && "$(readlink -f -- "$root")" == "$root" \
      && "$(stat -c '%u:%g:%a' -- "$root")" == 0:0:700 ]] \
    || fip_tx_error 'el directorio del journal no es root:root 0700' || return 1
  if [[ -n "$created" || ( ! -e "$root/.owner" && ! -L "$root/.owner" ) ]]; then
    fip_tx_atomic_text "$root/.owner" 0600 "$FIP_TX_OWNER_CONTENT" || return 1
  fi
  fip_tx_regular_root_file "$root/.owner" 600 \
    && fip_tx_content_matches "$root/.owner" "$FIP_TX_OWNER_CONTENT" \
    || fip_tx_error 'el journal no acredita pertenencia a floating-ip' || return 1
  owner_tmp="$root/.owner.tmp"
  if [[ -e "$owner_tmp" || -L "$owner_tmp" ]]; then
    fip_tx_regular_root_file "$owner_tmp" 600 \
      && fip_tx_content_matches "$owner_tmp" "$FIP_TX_OWNER_CONTENT" || return 1
    rm -f -- "$owner_tmp" || return 1
    fip_tx_sync_dir "$root" || return 1
  fi
}

fip_tx_dir() { # <transaction root> <txid>
  printf '%s/tx-%s\n' "${1%/}" "$2"
}

fip_tx_repair_cleanup_tmp() { # <root>; crash before/after cleanup rename
  local root="$1" tmp="$1/cleanup.tmp" marker="$1/cleanup" value="" existing
  local txid active_file directory phase expected
  [[ -e "$tmp" || -L "$tmp" ]] || return 0
  fip_tx_regular_root_file "$tmp" 600 || return 1
  value="$(fip_tx_read_value "$tmp" \
    '^[0-9a-f]{32}\|(committed|rolled-back)$' 2>/dev/null || :)"
  if [[ -e "$marker" || -L "$marker" ]]; then
    existing="$(fip_tx_read_value "$marker" \
      '^[0-9a-f]{32}\|(committed|rolled-back)$')" || return 1
    [[ -z "$value" || "$existing" == "$value" ]] || return 1
  else
    active_file="$root/active"
    txid="$(fip_tx_read_value "$active_file" '^[0-9a-f]{32}$')" || return 1
    directory="$(fip_tx_dir "$root" "$txid")"
    fip_tx_validate_journal_dir "$directory" "$txid" || return 1
    phase="$(fip_tx_read_value "$directory/phase" \
      '^(committed|rolled-back)$')" || return 1
    expected="$txid|$phase"
    [[ -z "$value" || "$value" == "$expected" ]] || return 1
  fi
  rm -f -- "$tmp" || return 1
  fip_tx_sync_dir "$root"
}

fip_tx_validate_journal_dir() { # <journal dir> <txid>
  local directory="$1" txid="$2" read_txid
  fip_tx_valid_txid "$txid" || return 1
  [[ -d "$directory" && ! -L "$directory" \
      && "$(readlink -f -- "$directory")" == "$directory" \
      && "$(stat -c '%u:%g:%a' -- "$directory")" == 0:0:700 ]] \
    || fip_tx_error 'el directorio de transaccion no es root-only' || return 1
  fip_tx_regular_root_file "$directory/.owner" 600 \
    && fip_tx_content_matches "$directory/.owner" "$FIP_TX_OWNER_CONTENT" \
    || fip_tx_error 'el journal activo no tiene propietario valido' || return 1
  read_txid="$(fip_tx_read_value "$directory/.txid" '^[0-9a-f]{32}$')" || return 1
  [[ "$read_txid" == "$txid" ]] \
    || fip_tx_error 'el TXID no coincide con la transaccion activa' || return 1
  fip_tx_regular_root_file "$directory/phase" 600 || return 1
  fip_tx_read_value "$directory/phase" \
    '^(preparing|prepared|mutating|verified|commit-decided|committed|rolling-back|rolled-back)$' \
    >/dev/null
}

fip_tx_reap_staging() { # <staging directory> <txid>; never recursive
  local staging="$1" txid="$2" path
  [[ "$staging" == */.prepare-"$txid" && -d "$staging" && ! -L "$staging" \
      && "$(stat -c '%u:%g:%a' -- "$staging")" == 0:0:700 ]] || return 1
  for path in "$staging"/* "$staging"/.[!.]* "$staging"/..?*; do
    [[ -e "$path" || -L "$path" ]] || continue
    case "${path##*/}" in
      .owner|.txid|phase|.owner.tmp|.txid.tmp|phase.tmp)
        [[ -f "$path" && ! -L "$path" \
            && "$(stat -c '%u:%g:%h' -- "$path")" == 0:0:1 ]] || return 1
        rm -f -- "$path" || return 1
        ;;
      *) fip_tx_error 'el staging incompleto contiene un objeto desconocido'; return 1 ;;
    esac
  done
  rmdir -- "$staging" || return 1
}

fip_tx_recover_unpublished() { # <root>; publish one complete orphan, reap staging
  local root="$1" path base txid="" directory="" temp="" found_tx found_tmp read_txid
  local -a stagings=()
  [[ ! -e "$root/active" && ! -L "$root/active" ]] || return 0
  [[ ! -e "$root/cleanup" && ! -L "$root/cleanup" ]] || return 0
  for path in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [[ -e "$path" || -L "$path" ]] || continue
    base="${path##*/}"
    case "$base" in
      .owner) ;;
      .prepare-*)
        [[ "${base#.prepare-}" =~ ^[0-9a-f]{32}$ ]] || return 1
        stagings+=("$path")
        ;;
      tx-*)
        found_tx="${base#tx-}"
        fip_tx_valid_txid "$found_tx" || return 1
        [[ -z "$txid" || "$txid" == "$found_tx" ]] || {
          fip_tx_error 'hay mas de una transaccion no publicada'; return 1;
        }
        txid="$found_tx"; directory="$path"
        ;;
      .active-*.tmp)
        found_tmp="${base#.active-}"; found_tmp="${found_tmp%.tmp}"
        fip_tx_valid_txid "$found_tmp" || return 1
        fip_tx_regular_root_file "$path" 600 || return 1
        read_txid="$(fip_tx_read_value "$path" '^[0-9a-f]{32}$')" || return 1
        [[ "$read_txid" == "$found_tmp" ]] || return 1
        [[ -z "$txid" || "$txid" == "$found_tmp" ]] || {
          fip_tx_error 'active temporal no coincide con el journal huerfano'; return 1;
        }
        txid="$found_tmp"; temp="$path"
        ;;
      *) fip_tx_error "objeto no reconocido en la raiz del journal: $base"; return 1 ;;
    esac
  done
  for path in "${stagings[@]}"; do
    found_tx="${path##*/.prepare-}"
    if [[ -n "$txid" && "$found_tx" == "$txid" && -n "$directory" ]]; then
      fip_tx_error 'coexisten staging y journal publicado para el mismo TXID'
      return 1
    fi
    fip_tx_reap_staging "$path" "$found_tx" || return 1
  done
  [[ -n "$txid" ]] || { fip_tx_sync_dir "$root"; return 0; }
  [[ -n "$directory" ]] || directory="$(fip_tx_dir "$root" "$txid")"
  fip_tx_validate_journal_dir "$directory" "$txid" || return 1
  if [[ -z "$temp" ]]; then
    temp="$root/.active-$txid.tmp"
    (umask 077; printf '%s\n' "$txid" > "$temp") || return 1
    chown 0:0 -- "$temp" || return 1
    chmod 0600 -- "$temp" || return 1
    fip_tx_sync_file "$temp" || return 1
  fi
  ln -- "$temp" "$root/active" || return 1
  rm -f -- "$temp" || return 1
  fip_tx_sync_dir "$root"
}

fip_tx_begin() { # <transaction root> <txid>
  local root="$1" txid="$2" directory staging active_file active_tmp current path
  fip_tx_valid_txid "$txid" || fip_tx_error 'TXID no valido' || return 1
  fip_tx_open_root "$root" || return 1
  fip_tx_repair_cleanup_tmp "$root" || return 1
  fip_tx_recover_unpublished "$root" || return 1
  [[ ! -e "$root/cleanup" && ! -L "$root/cleanup" ]] \
    || fip_tx_error 'hay un cleanup durable pendiente' || return 1
  directory="$(fip_tx_dir "$root" "$txid")" || return 1
  staging="$root/.prepare-$txid"
  active_file="$root/active"

  if [[ -e "$active_file" || -L "$active_file" ]]; then
    fip_tx_require_active "$root" "$txid" && return 0
    fip_tx_error 'ya existe otra transaccion activa'
    return 1
  fi

  # El directorio se construye completamente fuera de la referencia `active`.
  # Un crash aqui deja como mucho un staging no publicado; nunca un active a
  # medias. Un reintento del mismo TXID retira solo sus nombres conocidos.
  if [[ -e "$staging" || -L "$staging" ]]; then
    fip_tx_reap_staging "$staging" "$txid" || return 1
  fi

  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    (umask 077; mkdir -- "$staging") || return 1
    chown 0:0 -- "$staging" || return 1
    chmod 0700 -- "$staging" || return 1
    fip_tx_atomic_text "$staging/.owner" 0600 "$FIP_TX_OWNER_CONTENT" || return 1
    fip_tx_atomic_text "$staging/.txid" 0600 "$txid" || return 1
    fip_tx_atomic_text "$staging/phase" 0600 preparing || return 1
    fip_tx_sync_dir "$staging" || return 1
    mv -- "$staging" "$directory" || return 1
    fip_tx_sync_dir "$root" || return 1
  fi
  fip_tx_validate_journal_dir "$directory" "$txid" || return 1

  active_tmp="$root/.active-$txid.tmp"
  if [[ -e "$active_tmp" || -L "$active_tmp" ]]; then
    fip_tx_regular_root_file "$active_tmp" 600 || return 1
    rm -f -- "$active_tmp" || return 1
  fi
  (umask 077; printf '%s\n' "$txid" > "$active_tmp") || return 1
  chown 0:0 -- "$active_tmp" || return 1
  chmod 0600 -- "$active_tmp" || return 1
  fip_tx_sync_file "$active_tmp" || return 1
  if ! ln -- "$active_tmp" "$active_file"; then
    rm -f -- "$active_tmp"
    current="$(fip_tx_discover "$root")" || return 1
    [[ "$current" == txid="$txid"* ]] && return 0
    fip_tx_error 'otra transaccion gano la publicacion atomica de active'
    return 1
  fi
  rm -f -- "$active_tmp" || return 1
  fip_tx_sync_dir "$root" || return 1
  fip_tx_require_active "$root" "$txid"
}

fip_tx_repair_active_link() { # <transaction root>
  local root="$1" active_file="$1/active" txid tmp active_stat tmp_stat links bytes
  [[ -e "$active_file" || -L "$active_file" ]] || return 0
  fip_tx_regular_root_file "$active_file" 600 allow-two || return 1
  IFS= read -r txid < "$active_file" || return 1
  fip_tx_valid_txid "$txid" || return 1
  bytes="$(wc -c < "$active_file")" || return 1
  [[ "$bytes" -eq $(( ${#txid} + 1 )) ]] || return 1
  links="$(stat -c %h -- "$active_file")" || return 1
  [[ "$links" == 2 ]] || return 0
  tmp="$root/.active-$txid.tmp"
  fip_tx_regular_root_file "$tmp" 600 allow-two || return 1
  active_stat="$(stat -c '%d:%i' -- "$active_file")" || return 1
  tmp_stat="$(stat -c '%d:%i' -- "$tmp")" || return 1
  [[ "$active_stat" == "$tmp_stat" ]] || return 1
  rm -f -- "$tmp" || return 1
  fip_tx_sync_dir "$root" || return 1
  fip_tx_regular_root_file "$active_file" 600
}

fip_tx_discover() { # <transaction root> -> none | txid=...;phase=...;decision=...
  local root="$1" active_file txid directory phase decision=none cleanup
  fip_tx_assert_components "$root" || return 1
  if [[ ! -e "$root" && ! -L "$root" ]]; then
    printf '%s\n' none
    return 0
  fi
  fip_tx_open_root "$root" || return 1
  fip_tx_repair_cleanup_tmp "$root" || return 1
  if [[ -e "$root/cleanup" || -L "$root/cleanup" ]]; then
    cleanup="$(fip_tx_read_value "$root/cleanup" \
      '^[0-9a-f]{32}\|(committed|rolled-back)$')" || return 1
    IFS='|' read -r txid phase <<< "$cleanup"
    [[ "$phase" != committed ]] || decision=commit
    printf 'txid=%s;phase=%s;decision=%s\n' "$txid" "$phase" "$decision"
    return 0
  fi
  fip_tx_recover_unpublished "$root" || return 1
  active_file="$root/active"
  if [[ ! -e "$active_file" && ! -L "$active_file" ]]; then
    printf '%s\n' none
    return 0
  fi
  fip_tx_repair_active_link "$root" || return 1
  txid="$(fip_tx_read_value "$active_file" '^[0-9a-f]{32}$')" || return 1
  directory="$(fip_tx_dir "$root" "$txid")" || return 1
  fip_tx_validate_journal_dir "$directory" "$txid" || return 1
  phase="$(fip_tx_read_value "$directory/phase" \
    '^(preparing|prepared|mutating|verified|commit-decided|committed|rolling-back|rolled-back)$')" \
    || return 1
  if [[ -e "$directory/decision" || -L "$directory/decision" ]]; then
    decision="$(fip_tx_read_value "$directory/decision" '^commit$')" || return 1
  fi
  printf 'txid=%s;phase=%s;decision=%s\n' "$txid" "$phase" "$decision"
}

fip_tx_recovery_action() { # <transaction root>
  local discovered txid phase decision
  discovered="$(fip_tx_discover "$1")" || return 1
  [[ "$discovered" != none ]] || { printf '%s\n' none; return 0; }
  [[ "$discovered" =~ ^txid=([0-9a-f]{32})\;phase=([a-z-]+)\;decision=(none|commit)$ ]] \
    || return 1
  txid="${BASH_REMATCH[1]}"; phase="${BASH_REMATCH[2]}"; decision="${BASH_REMATCH[3]}"
  if [[ "$phase" == committed || "$phase" == rolled-back ]]; then
    printf 'cleanup:%s\n' "$txid"
  elif [[ "$decision" == commit ]]; then
    printf 'commit:%s\n' "$txid"
  else
    printf 'rollback:%s\n' "$txid"
  fi
}

fip_tx_require_active() { # <transaction root> <txid>
  local root="$1" txid="$2" active_file directory read_txid
  fip_tx_valid_txid "$txid" || return 1
  fip_tx_open_root "$root" || return 1
  active_file="$root/active"
  fip_tx_repair_active_link "$root" || return 1
  read_txid="$(fip_tx_read_value "$active_file" '^[0-9a-f]{32}$')" || return 1
  [[ "$read_txid" == "$txid" ]] || return 1
  directory="$(fip_tx_dir "$root" "$txid")" || return 1
  fip_tx_validate_journal_dir "$directory" "$txid"
}

fip_tx_read_value() { # <file> <regex>
  local file="$1" regex="$2" value bytes
  fip_tx_regular_root_file "$file" 600 || return 1
  IFS= read -r value < "$file" || return 1
  bytes="$(wc -c < "$file")" || return 1
  [[ "$bytes" -eq $(( ${#value} + 1 )) ]] || return 1
  [[ "$value" =~ $regex ]] || return 1
  printf '%s\n' "$value"
}

fip_tx_phase() { # <transaction root> <txid>
  local active
  fip_tx_require_active "$1" "$2" || return 1
  active="$(fip_tx_dir "$1" "$2")"
  fip_tx_read_value "$active/phase" \
    '^(preparing|prepared|mutating|verified|commit-decided|committed|rolling-back|rolled-back)$'
}

fip_tx_set_phase() { # <transaction root> <txid> <phase>
  local root="$1" txid="$2" phase="$3" active
  [[ "$phase" =~ ^(preparing|prepared|mutating|verified|commit-decided|committed|rolling-back|rolled-back)$ ]] \
    || return 1
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_atomic_text "$active/phase" 0600 "$phase"
}

fip_tx_set_mode() { # <transaction root> <txid> <v2|legacy>; before freeze
  local root="$1" txid="$2" mode="$3" active phase existing
  [[ "$mode" == v2 || "$mode" == legacy ]] || return 1
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if [[ -e "$active/deployment.mode" || -L "$active/deployment.mode" ]]; then
    existing="$(fip_tx_read_value "$active/deployment.mode" '^(v2|legacy)$')" || return 1
    [[ "$existing" == "$mode" ]] \
      || fip_tx_error 'el modo de una transaccion publicada es inmutable' || return 1
    return 0
  fi
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" == preparing && -e "$active/paths.meta" \
      && ! -e "$active/freeze.meta" && ! -e "$active/snapshot.complete" ]] \
    || fip_tx_error 'el modo debe fijarse tras preparar rutas y antes del freeze' \
    || return 1
  fip_tx_atomic_text "$active/deployment.mode" 0600 "$mode"
}

fip_tx_get_mode() { # <transaction root> <txid> -> v2 | legacy
  local active
  fip_tx_require_active "$1" "$2" || return 1
  active="$(fip_tx_dir "$1" "$2")"
  fip_tx_read_value "$active/deployment.mode" '^(v2|legacy)$'
}

fip_tx_baseline() { # <transaction root> <txid> -> none | snapshot | quiesced
  local root="$1" txid="$2" active snapshot="" quiesced="" mode
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  mode="$(fip_tx_get_mode "$root" "$txid")" || return 1
  if [[ -e "$active/snapshot.complete" || -L "$active/snapshot.complete" ]]; then
    [[ "$(fip_tx_read_value "$active/snapshot.complete" '^[0-9a-f]{32}$')" == "$txid" ]] \
      || return 1
    snapshot=1
  fi
  if [[ -e "$active/quiesced.complete" || -L "$active/quiesced.complete" ]]; then
    [[ "$(fip_tx_read_value "$active/quiesced.complete" '^[0-9a-f]{32}$')" == "$txid" ]] \
      || return 1
    [[ -n "$snapshot" && "$mode" == legacy ]] \
      || fip_tx_error 'baseline quiesced incoherente con modo/snapshot' || return 1
    quiesced=1
  fi
  if [[ -n "$quiesced" ]]; then
    printf '%s\n' quiesced
  elif [[ -n "$snapshot" ]]; then
    printf '%s\n' snapshot
  else
    printf '%s\n' none
  fi
}

fip_tx_hash_text() {
  local value
  value="$(printf '%s' "$1" | sha256sum)" || return 1
  printf '%s\n' "${value%% *}"
}

fip_tx_assert_paths_match() { # <active> <data> <template>
  local active="$1" data="$2" template="$3" expected actual
  expected="$(fip_tx_read_value "$active/paths.meta" '^[0-9a-f]{64}\|[0-9a-f]{64}$')" \
    || return 1
  actual="$(fip_tx_hash_text "$data")|$(fip_tx_hash_text "$template")" || return 1
  [[ "$expected" == "$actual" ]] \
    || fip_tx_error 'las rutas no coinciden con el snapshot' || return 1
}

fip_tx_remove_known_file() { # <path> [mode]
  local path="$1" mode="${2:-600}"
  if [[ -e "$path" || -L "$path" ]]; then
    fip_tx_regular_root_file "$path" "$mode" \
      || fip_tx_error "objeto conocido inseguro: $path" || return 1
    rm -f -- "$path" || return 1
  fi
}

fip_tx_snapshot_one() { # <source> <copy> <meta> <kind>
  local source="$1" copy="$2" meta="$3" kind="$4"
  local before after uid gid mode links size dev inode sha_before sha_copy
  if [[ ! -e "$source" && ! -L "$source" ]]; then
    fip_tx_remove_known_file "$copy" 600 || return 1
    fip_tx_atomic_text "$meta" 0600 absent
    return
  fi
  [[ -f "$source" && ! -L "$source" && "$(readlink -f -- "$source")" == "$source" ]] \
    || fip_tx_error "el origen del snapshot no es regular: $source" || return 1
  before="$(stat -c '%u|%g|%a|%h|%s|%d|%i' -- "$source")" || return 1
  IFS='|' read -r uid gid mode links size dev inode <<< "$before"
  [[ "$uid" == 0 && "$gid" == 0 && "$links" == 1 \
      && "$size" =~ ^[0-9]+$ && "$size" -le 2097152 ]] \
    || fip_tx_error "metadatos inseguros en $source" || return 1
  if [[ "$kind" == state ]]; then
    [[ "$mode" == 600 ]] \
      || fip_tx_error "el estado debe ser root:root 0600: $source" || return 1
  else
    [[ "$mode" == 600 || "$mode" == 644 ]] \
      || fip_tx_error "modo de plantilla no admitido: $mode" || return 1
  fi
  sha_before="$(sha256sum -- "$source")" || return 1
  sha_before="${sha_before%% *}"
  fip_tx_remove_known_file "$copy" 600 || return 1
  cp -- "$source" "$copy" || return 1
  chown 0:0 -- "$copy" || return 1
  chmod 0600 -- "$copy" || return 1
  fip_tx_regular_root_file "$copy" 600 || return 1
  fip_tx_sync_file "$copy" || return 1
  sha_copy="$(sha256sum -- "$copy")" || return 1
  sha_copy="${sha_copy%% *}"
  after="$(stat -c '%u|%g|%a|%h|%s|%d|%i' -- "$source")" || return 1
  [[ "$after" == "$before" && "$sha_copy" == "$sha_before" ]] \
    || fip_tx_error "el origen cambio durante el snapshot: $source" || return 1
  fip_tx_atomic_text "$meta" 0600 "present|$mode|$size|$sha_before"
}

fip_tx_prepare_paths() { # <transaction root> <txid> <data dir> <template file>
  local root="$1" txid="$2" data="$3" template="$4" active data_state phase
  fip_tx_validate_paths "$data" "$template" "$root" || return 1
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" == preparing ]] \
    || fip_tx_error "no se pueden preparar rutas en fase $phase" || return 1
  if [[ -e "$active/paths.meta" || -L "$active/paths.meta" ]]; then
    fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
    fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$' >/dev/null
    return
  fi
  if [[ ! -e "$data" && ! -L "$data" ]]; then
    data_state=absent
  else
    [[ -d "$data" && ! -L "$data" && "$(readlink -f -- "$data")" == "$data" \
        && "$(stat -c '%u:%g:%a' -- "$data")" == 0:0:700 ]] \
      || fip_tx_error 'el directorio de datos no es root:root 0700' || return 1
    data_state=present
  fi
  # data-dir.meta se hace durable antes de crear la barrera: en fresh-install
  # el directorio que cree .deploy-freeze nunca se confunde con preexistente.
  fip_tx_atomic_text "$active/data-dir.meta" 0600 "$data_state" || return 1
  fip_tx_atomic_text "$active/paths.meta" 0600 \
    "$(fip_tx_hash_text "$data")|$(fip_tx_hash_text "$template")"
}

fip_tx_snapshot() { # <transaction root> <txid> <data dir> <template file>
  local root="$1" txid="$2" data="$3" template="$4" active phase
  local data_state name key index
  local -a names=(
    pool.json pool.json.lock security.json security.json.lock keepalived.conf
    .cluster-protocol-v2 .bootstrap-pool .bootstrap-security
  )
  local -a keys=(
    pool pool-lock security security-lock config protocol
    bootstrap-pool bootstrap-security
  )
  fip_tx_prepare_paths "$root" "$txid" "$data" "$template" || return 1
  fip_tx_get_mode "$root" "$txid" >/dev/null || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  if [[ "$phase" == prepared ]]; then
    fip_tx_assert_paths_match "$active" "$data" "$template"
    return
  fi
  [[ "$phase" == preparing ]] \
    || fip_tx_error "no se puede crear snapshot en fase $phase" || return 1

  data_state="$(fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$')" || return 1
  if [[ "$data_state" == present ]]; then
    [[ -d "$data" && ! -L "$data" && "$(readlink -f -- "$data")" == "$data" \
        && "$(stat -c '%u:%g:%a' -- "$data")" == 0:0:700 ]] \
      || fip_tx_error 'el directorio de datos no es root:root 0700' || return 1
  fi

  for index in "${!names[@]}"; do
    name="${names[$index]}"; key="${keys[$index]}"
    if [[ "$data_state" == absent ]]; then
      fip_tx_remove_known_file "$active/snapshot.$key" 600 || return 1
      fip_tx_atomic_text "$active/snapshot.$key.meta" 0600 absent || return 1
    else
      fip_tx_snapshot_one "$data/$name" "$active/snapshot.$key" \
        "$active/snapshot.$key.meta" state || return 1
    fi
  done
  fip_tx_snapshot_one "$template" "$active/snapshot.template" \
    "$active/snapshot.template.meta" template || return 1
  fip_tx_atomic_text "$active/snapshot.complete" 0600 "$txid" || return 1
  fip_tx_set_phase "$root" "$txid" prepared
}

fip_tx_snapshot_prefix() { # <active journal dir> <txid>
  [[ "$(fip_tx_read_value "$1/snapshot.complete" '^[0-9a-f]{32}$')" == "$2" ]] \
    || return 1
  if [[ -e "$1/quiesced.complete" || -L "$1/quiesced.complete" ]]; then
    [[ "$(fip_tx_read_value "$1/quiesced.complete" '^[0-9a-f]{32}$')" == "$2" ]] \
      || return 1
    printf '%s\n' quiesced
  else
    printf '%s\n' snapshot
  fi
}

fip_tx_snapshot_quiesced() { # <root> <txid> <data> <template>; legacy N/N stopped
  local root="$1" txid="$2" data="$3" template="$4" active data_state
  local cid rollback observed running name key index
  local -a names=(
    pool.json pool.json.lock security.json security.json.lock keepalived.conf
    .cluster-protocol-v2 .bootstrap-pool .bootstrap-security
  )
  local -a keys=(
    pool pool-lock security security-lock config protocol
    bootstrap-pool bootstrap-security
  )
  fip_tx_require_active "$root" "$txid" || return 1
  [[ "$(fip_tx_get_mode "$root" "$txid")" == legacy ]] \
    || fip_tx_error 'el baseline quiesced solo corresponde a legacy' || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  [[ "$(fip_tx_phase "$root" "$txid")" == mutating ]] || return 1
  [[ ! -e "$active/candidate.cid" && ! -L "$active/candidate.cid" ]] \
    || fip_tx_error 'no se puede fijar baseline quiesced tras arrancar candidato' \
    || return 1
  cid="$(fip_tx_read_value "$active/old.cid" '^(absent|[0-9a-f]{64})$')" || return 1
  if [[ "$cid" != absent ]]; then
    rollback="$(fip_tx_read_value "$active/old.rollback-name" \
      '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
    observed="$(docker inspect --format '{{.Id}}' "$rollback")" || return 1
    running="$(docker inspect --format '{{.State.Running}}' "$cid")" || return 1
    [[ "$observed" == "$cid" && "$running" == false ]] \
      || fip_tx_error 'el contenedor legacy no esta preservado y detenido' || return 1
  fi
  data_state="$(fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$')" || return 1
  for index in "${!names[@]}"; do
    name="${names[$index]}"; key="${keys[$index]}"
    if [[ "$data_state" == absent ]]; then
      fip_tx_remove_known_file "$active/quiesced.$key" 600 || return 1
      fip_tx_atomic_text "$active/quiesced.$key.meta" 0600 absent || return 1
    else
      fip_tx_snapshot_one "$data/$name" "$active/quiesced.$key" \
        "$active/quiesced.$key.meta" state || return 1
    fi
  done
  fip_tx_snapshot_one "$template" "$active/quiesced.template" \
    "$active/quiesced.template.meta" template || return 1
  fip_tx_atomic_text "$active/quiesced.complete" 0600 "$txid"
}

fip_tx_read_snapshot_meta() { # <meta path>
  fip_tx_read_value "$1" \
    '^(absent|present\|(600|644)\|[0-9]{1,8}\|[0-9a-f]{64})$'
}

fip_tx_restore_one() { # <copy> <meta> <target> <kind> <txid>
  local copy="$1" meta_file="$2" target="$3" kind="$4" txid="$5"
  local meta status mode size sha actual tmp parent
  meta="$(fip_tx_read_snapshot_meta "$meta_file")" || return 1
  if [[ "$meta" == absent ]]; then
    if [[ -e "$target" || -L "$target" ]]; then
      [[ -f "$target" && ! -L "$target" && "$(readlink -f -- "$target")" == "$target" \
          && "$(stat -c '%u:%g:%h' -- "$target")" == 0:0:1 ]] \
        || fip_tx_error "no se retirara un objeto no administrable: $target" || return 1
      rm -f -- "$target" || return 1
      parent="${target%/*}"; [[ -n "$parent" ]] || parent=/
      fip_tx_sync_dir "$parent" || return 1
    fi
    return 0
  fi
  IFS='|' read -r status mode size sha <<< "$meta"
  [[ "$status" == present ]] || return 1
  [[ "$kind" != state || "$mode" == 600 ]] || return 1
  fip_tx_regular_root_file "$copy" 600 || return 1
  [[ "$(stat -c %s -- "$copy")" == "$size" ]] || return 1
  actual="$(sha256sum -- "$copy")" || return 1
  actual="${actual%% *}"
  [[ "$actual" == "$sha" ]] || fip_tx_error "snapshot alterado: $copy" || return 1
  parent="${target%/*}"; [[ -n "$parent" ]] || parent=/
  [[ -d "$parent" && ! -L "$parent" && "$(readlink -f -- "$parent")" == "$parent" ]] \
    || fip_tx_error "el padre de restauracion no es real: $parent" || return 1
  tmp="$target.fip-tx-$txid.tmp"
  if [[ -e "$tmp" || -L "$tmp" ]]; then
    fip_tx_regular_root_file "$tmp" 600 \
      || fip_tx_error "temporal de restauracion inseguro: $tmp" || return 1
    rm -f -- "$tmp" || return 1
  fi
  cp -- "$copy" "$tmp" || return 1
  chown 0:0 -- "$tmp" || return 1
  chmod 0600 -- "$tmp" || return 1
  fip_tx_sync_file "$tmp" || return 1
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" && "$(readlink -f -- "$target")" == "$target" \
        && "$(stat -c '%u:%g:%h' -- "$target")" == 0:0:1 ]] \
      || fip_tx_error "destino de restauracion inseguro: $target" || return 1
  fi
  mv -f -- "$tmp" "$target" || return 1
  chmod "$mode" -- "$target" || return 1
  fip_tx_sync_file "$target" || return 1
  fip_tx_sync_dir "$parent" || return 1
  actual="$(sha256sum -- "$target")" || return 1
  [[ "${actual%% *}" == "$sha" ]]
}

fip_tx_resume_freeze() { # <active> <data> <txid>; 0 complete, 2 recreate
  local active="$1" data="$2" txid="$3" meta dev inode sha marker tmp
  local path stat_line actual marker_exists="" tmp_exists=""
  meta="$(fip_tx_read_value "$active/freeze.meta" \
    '^[0-9]+\|[0-9]+\|[0-9a-f]{64}$')" || return 1
  IFS='|' read -r dev inode sha <<< "$meta"
  marker="$data/.deploy-freeze"
  tmp="$data/.deploy-freeze.$txid.tmp"
  [[ ! -e "$marker" && ! -L "$marker" ]] || marker_exists=1
  [[ ! -e "$tmp" && ! -L "$tmp" ]] || tmp_exists=1
  if [[ -z "$marker_exists" && -z "$tmp_exists" ]]; then
    # El objeto aun no se habia publicado (o se perdio antes de cualquier
    # mutacion). Retirar solo el metadato conocido permite recrearlo.
    fip_tx_remove_known_file "$active/freeze.meta" 600 || return 1
    return 2
  fi
  for path in "$marker" "$tmp"; do
    [[ -e "$path" || -L "$path" ]] || continue
    fip_tx_regular_root_file "$path" 600 allow-two \
      || fip_tx_error "barrera parcial insegura: $path" || return 1
    stat_line="$(stat -c '%d|%i' -- "$path")" || return 1
    actual="$(sha256sum -- "$path")"; actual="${actual%% *}"
    [[ "$stat_line" == "$dev|$inode" && "$actual" == "$sha" ]] \
      || fip_tx_error 'la barrera parcial no pertenece a este TXID' || return 1
  done
  if [[ -z "$marker_exists" ]]; then
    ln -- "$tmp" "$marker" || return 1
    marker_exists=1
  fi
  if [[ -n "$tmp_exists" ]]; then
    rm -f -- "$tmp" || return 1
  fi
  fip_tx_sync_dir "$data" || return 1
  fip_tx_regular_root_file "$marker" 600 || return 1
  stat_line="$(stat -c '%d|%i' -- "$marker")" || return 1
  [[ "$stat_line" == "$dev|$inode" ]] || return 1
  fip_tx_content_matches "$marker" "$FIP_TX_FREEZE_CONTENT"
}

fip_tx_install_freeze() { # <transaction root> <txid> <data dir> <template>
  local root="$1" txid="$2" data="$3" template="$4" active data_state
  local marker tmp stat_line dev inode sha meta
  fip_tx_require_active "$root" "$txid" || return 1
  fip_tx_get_mode "$root" "$txid" >/dev/null || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  data_state="$(fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$')" || return 1
  marker="$data/.deploy-freeze"
  tmp="$data/.deploy-freeze.$txid.tmp"
  if [[ -e "$active/freeze.meta" || -L "$active/freeze.meta" ]]; then
    if fip_tx_resume_freeze "$active" "$data" "$txid"; then
      return 0
    else
      local resume_status=$?
      [[ "$resume_status" == 2 ]] || return "$resume_status"
    fi
  fi
  if [[ "$data_state" == absent ]]; then
    if [[ ! -e "$data" && ! -L "$data" ]]; then
      local parent="${data%/*}"; [[ -n "$parent" ]] || parent=/
      [[ -d "$parent" && ! -L "$parent" ]] || return 1
      (umask 077; mkdir -- "$data") || return 1
      chown 0:0 -- "$data" || return 1
      chmod 0700 -- "$data" || return 1
    fi
  fi
  [[ -d "$data" && ! -L "$data" && "$(readlink -f -- "$data")" == "$data" \
      && "$(stat -c '%u:%g:%a' -- "$data")" == 0:0:700 ]] || return 1
  [[ ! -e "$marker" && ! -L "$marker" ]] \
    || fip_tx_error 'ya existe una barrera de despliegue no atribuible a este TXID' \
    || return 1
  if [[ -e "$tmp" || -L "$tmp" ]]; then
    fip_tx_regular_root_file "$tmp" 600 || return 1
    rm -f -- "$tmp" || return 1
  fi
  (umask 077; printf '%s\n' "$FIP_TX_FREEZE_CONTENT" > "$tmp") || return 1
  chown 0:0 -- "$tmp" || return 1
  chmod 0600 -- "$tmp" || return 1
  fip_tx_regular_root_file "$tmp" 600 || return 1
  fip_tx_content_matches "$tmp" "$FIP_TX_FREEZE_CONTENT" || return 1
  fip_tx_sync_file "$tmp" || return 1
  stat_line="$(stat -c '%d|%i' -- "$tmp")" || return 1
  IFS='|' read -r dev inode <<< "$stat_line"
  sha="$(sha256sum -- "$tmp")"; sha="${sha%% *}"
  fip_tx_atomic_text "$active/freeze.meta" 0600 "$dev|$inode|$sha" || return 1
  if ! ln -- "$tmp" "$marker"; then
    rm -f -- "$tmp"
    return 1
  fi
  rm -f -- "$tmp" || return 1
  fip_tx_sync_dir "$data" || return 1
  fip_tx_regular_root_file "$marker" 600 \
    && fip_tx_content_matches "$marker" "$FIP_TX_FREEZE_CONTENT"
}

fip_tx_remove_freeze() { # <transaction root> <txid> <data dir> <template>
  local root="$1" txid="$2" data="$3" template="$4" active meta
  local dev inode sha marker tmp path stat_line actual
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  [[ -e "$active/freeze.meta" || -L "$active/freeze.meta" ]] || return 0
  meta="$(fip_tx_read_value "$active/freeze.meta" '^[0-9]+\|[0-9]+\|[0-9a-f]{64}$')" \
    || return 1
  IFS='|' read -r dev inode sha <<< "$meta"
  marker="$data/.deploy-freeze"
  tmp="$data/.deploy-freeze.$txid.tmp"
  for path in "$marker" "$tmp"; do
    [[ -e "$path" || -L "$path" ]] || continue
    fip_tx_regular_root_file "$path" 600 allow-two \
      || fip_tx_error "barrera de despliegue insegura: $path" || return 1
    stat_line="$(stat -c '%d|%i' -- "$path")" || return 1
    actual="$(sha256sum -- "$path")"; actual="${actual%% *}"
    [[ "$stat_line" == "$dev|$inode" && "$actual" == "$sha" ]] \
      || fip_tx_error 'la barrera ya no pertenece a esta transaccion' || return 1
  done
  [[ ! -e "$marker" && ! -L "$marker" ]] || rm -f -- "$marker" || return 1
  [[ ! -e "$tmp" && ! -L "$tmp" ]] || rm -f -- "$tmp" || return 1
  [[ ! -d "$data" ]] || fip_tx_sync_dir "$data" || return 1
}

fip_tx_stage_template() { # <root> <txid> <data> <template>; bytes on stdin
  local root="$1" txid="$2" data="$3" template="$4" active tmp bytes sha
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  tmp="$active/template.candidate.tmp"
  fip_tx_remove_known_file "$tmp" 600 || return 1
  (umask 077; : > "$tmp") || return 1
  cat > "$tmp" || return 1
  chown 0:0 -- "$tmp" || return 1
  chmod 0600 -- "$tmp" || return 1
  bytes="$(wc -c < "$tmp")" || return 1
  [[ "$bytes" -gt 0 && "$bytes" -le 1048576 ]] || return 1
  fip_tx_sync_file "$tmp" || return 1
  sha="$(sha256sum -- "$tmp")"; sha="${sha%% *}"
  mv -f -- "$tmp" "$active/template.candidate" || return 1
  fip_tx_atomic_text "$active/template.candidate.meta" 0600 "$bytes|$sha"
}

fip_tx_install_template() { # <root> <txid> <data> <template>
  local root="$1" txid="$2" data="$3" template="$4" active candidate_meta
  local bytes sha snapshot_meta status old_mode old_size old_sha actual parent tmp prefix
  local installing_sha installed_sha phase
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  # Publicar la plantilla es parte del lado commit de la saga. La comprobacion
  # remota no confia en que el coordinador haya llamado las funciones en orden:
  # tanto la decision como su fase durable deben existir antes de tocar /boot.
  [[ "$(fip_tx_read_value "$active/decision" '^commit$')" == commit ]] \
    || fip_tx_error 'la plantilla no puede publicarse antes de decidir commit' \
    || return 1
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" == commit-decided || "$phase" == committed ]] \
    || fip_tx_error 'la fase no autoriza publicar la plantilla' || return 1
  candidate_meta="$(fip_tx_read_value "$active/template.candidate.meta" \
    '^[0-9]{1,7}\|[0-9a-f]{64}$')" || return 1
  IFS='|' read -r bytes sha <<< "$candidate_meta"
  fip_tx_regular_root_file "$active/template.candidate" 600 || return 1
  [[ "$(stat -c %s -- "$active/template.candidate")" == "$bytes" ]] || return 1
  actual="$(sha256sum -- "$active/template.candidate")"; actual="${actual%% *}"
  [[ "$actual" == "$sha" ]] || return 1

  # Recovery windows around publication of the template:
  #   installing -> mv -> installed
  # An already published candidate is a successful retry, not evidence that the
  # pre-deployment template changed. Validate bytes, ownership and mode before
  # accepting it; journal files alone never authorize an overwrite.
  if [[ -e "$active/template.installed.sha" ]]; then
    installed_sha="$(fip_tx_read_value "$active/template.installed.sha" \
      '^[0-9a-f]{64}$')" || return 1
    [[ "$installed_sha" == "$sha" ]] || return 1
    if [[ -e "$active/template.installing.sha" ]]; then
      installing_sha="$(fip_tx_read_value "$active/template.installing.sha" \
        '^[0-9a-f]{64}$')" || return 1
      [[ "$installing_sha" == "$sha" ]] || return 1
    fi
    [[ -f "$template" && ! -L "$template" && "$(readlink -f -- "$template")" == "$template" \
        && "$(stat -c '%u:%g:%a:%h:%s' -- "$template")" == "0:0:600:1:$bytes" ]] \
      || return 1
    actual="$(sha256sum -- "$template")"; actual="${actual%% *}"
    [[ "$actual" == "$sha" ]] || return 1
    return 0
  fi
  if [[ -e "$active/template.installing.sha" ]]; then
    installing_sha="$(fip_tx_read_value "$active/template.installing.sha" \
      '^[0-9a-f]{64}$')" || return 1
    [[ "$installing_sha" == "$sha" ]] || return 1
    if [[ -f "$template" && ! -L "$template" \
        && "$(readlink -f -- "$template")" == "$template" \
        && "$(stat -c '%u:%g:%a:%h:%s' -- "$template")" == "0:0:600:1:$bytes" ]]; then
      actual="$(sha256sum -- "$template")"; actual="${actual%% *}"
      if [[ "$actual" == "$sha" ]]; then
        fip_tx_atomic_text "$active/template.installed.sha" 0600 "$sha"
        return
      fi
    fi
  fi

  prefix="$(fip_tx_snapshot_prefix "$active" "$txid")" || return 1
  snapshot_meta="$(fip_tx_read_snapshot_meta "$active/$prefix.template.meta")" || return 1
  if [[ "$snapshot_meta" == absent ]]; then
    [[ ! -e "$template" && ! -L "$template" ]] \
      || fip_tx_error 'la plantilla aparecio despues del snapshot' || return 1
  else
    IFS='|' read -r status old_mode old_size old_sha <<< "$snapshot_meta"
    [[ "$status" == present ]] || return 1
    [[ -f "$template" && ! -L "$template" && "$(readlink -f -- "$template")" == "$template" \
        && "$(stat -c '%u:%g:%a:%h:%s' -- "$template")" \
          == "0:0:$old_mode:1:$old_size" ]] || return 1
    actual="$(sha256sum -- "$template")"; actual="${actual%% *}"
    [[ "$actual" == "$old_sha" ]] \
      || fip_tx_error 'la plantilla cambio despues del snapshot' || return 1
  fi
  parent="${template%/*}"; [[ -n "$parent" ]] || parent=/
  [[ -d "$parent" && ! -L "$parent" ]] || return 1
  fip_tx_atomic_text "$active/template.installing.sha" 0600 "$sha" || return 1
  tmp="$template.fip-tx-$txid.tmp"
  if [[ -e "$tmp" || -L "$tmp" ]]; then
    fip_tx_regular_root_file "$tmp" 600 || return 1
    rm -f -- "$tmp" || return 1
  fi
  cp -- "$active/template.candidate" "$tmp" || return 1
  chown 0:0 -- "$tmp" || return 1
  chmod 0600 -- "$tmp" || return 1
  fip_tx_sync_file "$tmp" || return 1
  mv -f -- "$tmp" "$template" || return 1
  fip_tx_sync_dir "$parent" || return 1
  actual="$(sha256sum -- "$template")"; actual="${actual%% *}"
  [[ "$actual" == "$sha" ]] || return 1
  fip_tx_atomic_text "$active/template.installed.sha" 0600 "$sha"
}

fip_tx_restore_snapshot() { # <root> <txid> <data> <template>
  local root="$1" txid="$2" data="$3" template="$4" active data_state
  local name key index installed expected current template_meta prefix
  local template_status template_mode template_size template_original_sha restore_template
  local -a names=(
    pool.json pool.json.lock security.json security.json.lock keepalived.conf
    .cluster-protocol-v2 .bootstrap-pool .bootstrap-security
  )
  local -a keys=(
    pool pool-lock security security-lock config protocol
    bootstrap-pool bootstrap-security
  )
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  [[ "$(fip_tx_phase "$root" "$txid")" == rolling-back ]] || return 1
  data_state="$(fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$')" || return 1
  prefix="$(fip_tx_snapshot_prefix "$active" "$txid")" || return 1
  if [[ ! -e "$data" && ! -L "$data" ]]; then
    local parent="${data%/*}"; [[ -n "$parent" ]] || parent=/
    [[ -d "$parent" && ! -L "$parent" ]] || return 1
    (umask 077; mkdir -- "$data") || return 1
    chown 0:0 -- "$data" || return 1
    chmod 0700 -- "$data" || return 1
  fi
  [[ -d "$data" && ! -L "$data" && "$(readlink -f -- "$data")" == "$data" \
      && "$(stat -c '%u:%g:%a' -- "$data")" == 0:0:700 ]] || return 1
  for index in "${!names[@]}"; do
    name="${names[$index]}"; key="${keys[$index]}"
    fip_tx_restore_one "$active/$prefix.$key" "$active/$prefix.$key.meta" \
      "$data/$name" state "$txid" || return 1
  done

  installed=""
  if [[ -e "$active/template.installed.sha" || -e "$active/template.installing.sha" ]]; then
    if [[ -e "$active/template.installed.sha" ]]; then
      installed="$active/template.installed.sha"
    else
      installed="$active/template.installing.sha"
    fi
    expected="$(fip_tx_read_value "$installed" '^[0-9a-f]{64}$')" || return 1
    template_meta="$(fip_tx_read_snapshot_meta "$active/$prefix.template.meta")" \
      || return 1
    template_original_sha=""
    if [[ "$template_meta" != absent ]]; then
      IFS='|' read -r template_status template_mode template_size template_original_sha \
        <<< "$template_meta"
      [[ "$template_status" == present ]] || return 1
    fi
    restore_template=1
    if [[ -e "$template" || -L "$template" ]]; then
      [[ -f "$template" && ! -L "$template" && "$(readlink -f -- "$template")" == "$template" \
          && "$(stat -c '%u:%g:%h' -- "$template")" == 0:0:1 ]] || return 1
      current="$(sha256sum -- "$template")"; current="${current%% *}"
      if [[ "$current" == "$expected" ]]; then
        restore_template=1
      elif [[ -n "$template_original_sha" && "$current" == "$template_original_sha" \
          && "$(stat -c '%a:%s' -- "$template")" \
            == "$template_mode:$template_size" ]]; then
        # Fallo despues de publicar "installing" pero antes del rename, o un
        # rollback anterior ya completo. No se vuelve a tocar la plantilla.
        restore_template=""
      else
        fip_tx_error 'la plantilla fue modificada por un tercero; no se sobrescribe'
        return 1
      fi
    elif [[ "$template_meta" == absent ]]; then
      restore_template=""
    fi
    if [[ -n "$restore_template" ]]; then
      fip_tx_restore_one "$active/$prefix.template" "$active/$prefix.template.meta" \
        "$template" template "$txid" || return 1
    fi
  fi
  [[ "$data_state" == present || "$(stat -c '%u:%g:%a' -- "$data")" == 0:0:700 ]]
}

fip_tx_docker_basic() { # <container ref> -> cid|running|paused
  docker inspect --format '{{.Id}}|{{.State.Running}}|{{.State.Paused}}' "$1"
}

fip_tx_wait_stopped() { # <cid>
  local cid="$1" timeout="${FIP_TX_TERM_TIMEOUT:-20}" count running
  [[ "$timeout" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ \
      && "$timeout" -le 120 ]] || return 1
  for ((count = 0; count < timeout; count += 1)); do
    if ! docker inspect "$cid" >/dev/null 2>&1; then
      return 0
    fi
    running="$(docker inspect --format '{{.State.Running}}' "$cid")" || return 1
    [[ "$running" == false ]] && return 0
    sleep 1
  done
  fip_tx_error "el contenedor $cid no termino tras SIGTERM; no se usara SIGKILL"
}

fip_tx_stop_term() { # <cid>
  local cid="$1" basic got_cid running paused
  basic="$(fip_tx_docker_basic "$cid")" || return 1
  IFS='|' read -r got_cid running paused <<< "$basic"
  [[ "$got_cid" == "$cid" && "$running" =~ ^(true|false)$ \
      && "$paused" =~ ^(true|false)$ ]] || return 1
  if [[ "$running" == true ]]; then
    if [[ "$paused" == true ]]; then
      docker unpause "$cid" >/dev/null || return 1
      basic="$(fip_tx_docker_basic "$cid")" || return 1
      IFS='|' read -r got_cid running paused <<< "$basic"
      [[ "$got_cid" == "$cid" && "$running" == true && "$paused" == false ]] \
        || fip_tx_error 'el contenedor cambio de identidad/estado tras unpause' \
        || return 1
    fi
    docker kill --signal=TERM "$cid" >/dev/null || return 1
    fip_tx_wait_stopped "$cid" || return 1
  fi
}

fip_tx_preserve_container() { # <root> <txid> <original name> <rollback name>
  local root="$1" txid="$2" original="$3" rollback="$4" active
  local basic cid running paused stored existing baseline
  fip_tx_valid_container_name "$original" && fip_tx_valid_container_name "$rollback" \
    && [[ "$original" != "$rollback" ]] || return 1
  fip_tx_require_active "$root" "$txid" || return 1
  baseline="$(fip_tx_baseline "$root" "$txid")" || return 1
  [[ "$baseline" == snapshot || "$baseline" == quiesced ]] \
    || fip_tx_error 'no se detendra un contenedor sin baseline completo' || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if [[ -e "$active/old.cid" ]]; then
    stored="$(fip_tx_read_value "$active/old.cid" '^(absent|[0-9a-f]{64})$')" || return 1
    [[ "$(fip_tx_read_value "$active/old.original-name" \
      '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" == "$original" ]] || return 1
    [[ "$(fip_tx_read_value "$active/old.rollback-name" \
      '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" == "$rollback" ]] || return 1
    [[ "$stored" != absent ]] || return 0
    cid="$stored"
  else
    fip_tx_atomic_text "$active/old.original-name" 0600 "$original" || return 1
    fip_tx_atomic_text "$active/old.rollback-name" 0600 "$rollback" || return 1
    if ! docker inspect "$original" >/dev/null 2>&1; then
      fip_tx_atomic_text "$active/old.cid" 0600 absent || return 1
      fip_tx_atomic_text "$active/old.was-running" 0600 false || return 1
      fip_tx_set_phase "$root" "$txid" mutating
      return
    fi
    basic="$(fip_tx_docker_basic "$original")" || return 1
    IFS='|' read -r cid running paused <<< "$basic"
    fip_tx_valid_cid "$cid" && [[ "$running" =~ ^(true|false)$ \
        && "$paused" =~ ^(true|false)$ ]] || return 1
    fip_tx_atomic_text "$active/old.cid" 0600 "$cid" || return 1
    fip_tx_atomic_text "$active/old.was-running" 0600 "$running" || return 1
  fi

  if docker inspect "$rollback" >/dev/null 2>&1; then
    existing="$(docker inspect --format '{{.Id}}' "$rollback")" || return 1
    [[ "$existing" == "$cid" ]] || fip_tx_error 'el nombre de rollback pertenece a otro contenedor' || return 1
    fip_tx_set_phase "$root" "$txid" mutating
    return
  fi
  docker inspect "$original" >/dev/null 2>&1 \
    || fip_tx_error 'se perdio el contenedor anterior antes del rename' || return 1
  existing="$(docker inspect --format '{{.Id}}' "$original")" || return 1
  [[ "$existing" == "$cid" ]] || fip_tx_error 'el nombre original cambio de CID' || return 1
  fip_tx_stop_term "$cid" || return 1
  docker rename "$cid" "$rollback" || return 1
  existing="$(docker inspect --format '{{.Id}}' "$rollback")" || return 1
  [[ "$existing" == "$cid" ]] || return 1
  fip_tx_set_phase "$root" "$txid" mutating
}

fip_tx_discover_candidate() { # <root> <txid> <container name> -> absent | CID
  local root="$1" txid="$2" name="$3" active line cid label_tx role old_cid stored
  fip_tx_valid_container_name "$name" || return 1
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if ! docker inspect "$name" >/dev/null 2>&1; then
    printf '%s\n' absent
    return 0
  fi
  line="$(docker inspect --format \
    '{{.Id}}|{{index .Config.Labels "io.ezr43l.deploy-transaction"}}|{{index .Config.Labels "io.ezr43l.deploy-role"}}' \
    "$name")" || return 1
  IFS='|' read -r cid label_tx role <<< "$line"
  fip_tx_valid_cid "$cid" || return 1
  if [[ -e "$active/old.cid" ]]; then
    old_cid="$(fip_tx_read_value "$active/old.cid" '^(absent|[0-9a-f]{64})$')" \
      || return 1
    if [[ "$old_cid" == "$cid" ]]; then
      printf '%s\n' absent
      return 0
    fi
  fi
  [[ "$label_tx" == "$txid" && "$role" == candidate ]] \
    || fip_tx_error 'el nombre esperado pertenece a un contenedor ajeno' || return 1
  if [[ -e "$active/candidate.cid" ]]; then
    stored="$(fip_tx_read_value "$active/candidate.cid" '^[0-9a-f]{64}$')" || return 1
    [[ "$stored" == "$cid" ]] \
      || fip_tx_error 'el CID candidato cambio despues de registrarse' || return 1
  else
    # Cierra la ventana docker-run -> escritura del journal: las etiquetas del
    # propio contenedor permiten reconstruir el CID sin confiar en el nombre.
    fip_tx_atomic_text "$active/candidate.cid" 0600 "$cid" || return 1
  fi
  printf '%s\n' "$cid"
}

fip_tx_record_candidate() { # <root> <txid> <container name> <cid>
  local root="$1" txid="$2" name="$3" cid="$4" discovered
  fip_tx_valid_container_name "$name" && fip_tx_valid_cid "$cid" || return 1
  discovered="$(fip_tx_discover_candidate "$root" "$txid" "$name")" || return 1
  [[ "$discovered" == "$cid" ]] \
    || fip_tx_error 'el candidato descubierto no coincide con docker run' || return 1
  fip_tx_set_phase "$root" "$txid" mutating
}

fip_tx_remove_candidate() { # <root> <txid>
  local root="$1" txid="$2" active cid observed label_tx role original discovered
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if [[ ! -e "$active/candidate.cid" ]]; then
    [[ -e "$active/old.original-name" ]] || return 0
    original="$(fip_tx_read_value "$active/old.original-name" \
      '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
    discovered="$(fip_tx_discover_candidate "$root" "$txid" "$original")" || return 1
    [[ "$discovered" != absent ]] || return 0
  fi
  cid="$(fip_tx_read_value "$active/candidate.cid" '^[0-9a-f]{64}$')" || return 1
  docker inspect "$cid" >/dev/null 2>&1 || return 0
  observed="$(docker inspect --format \
    '{{.Id}}|{{index .Config.Labels "io.ezr43l.deploy-transaction"}}|{{index .Config.Labels "io.ezr43l.deploy-role"}}' \
    "$cid")" || return 1
  IFS='|' read -r observed label_tx role <<< "$observed"
  [[ "$observed" == "$cid" && "$label_tx" == "$txid" && "$role" == candidate ]] \
    || fip_tx_error 'se rehusa eliminar un contenedor ajeno a la transaccion' \
    || return 1
  fip_tx_stop_term "$cid" || return 1
  docker rm "$cid" >/dev/null || return 1
  ! docker inspect "$cid" >/dev/null 2>&1
}

fip_tx_restore_old_container() { # <root> <txid>
  local root="$1" txid="$2" active cid original rollback was_running observed
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  [[ -e "$active/old.cid" ]] || return 0
  cid="$(fip_tx_read_value "$active/old.cid" '^(absent|[0-9a-f]{64})$')" || return 1
  [[ "$cid" != absent ]] || return 0
  original="$(fip_tx_read_value "$active/old.original-name" \
    '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
  rollback="$(fip_tx_read_value "$active/old.rollback-name" \
    '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
  was_running="$(fip_tx_read_value "$active/old.was-running" '^(true|false)$')" || return 1
  docker inspect "$cid" >/dev/null 2>&1 \
    || fip_tx_error 'el contenedor anterior ya no existe' || return 1
  if docker inspect "$original" >/dev/null 2>&1; then
    observed="$(docker inspect --format '{{.Id}}' "$original")" || return 1
    [[ "$observed" == "$cid" ]] \
      || fip_tx_error 'el nombre original pertenece a otro contenedor' || return 1
  else
    observed="$(docker inspect --format '{{.Id}}' "$rollback")" || return 1
    [[ "$observed" == "$cid" ]] || return 1
    docker rename "$cid" "$original" || return 1
  fi
  if [[ "$was_running" == true \
      && "$(docker inspect --format '{{.State.Running}}' "$cid")" != true ]]; then
    docker start "$cid" >/dev/null || return 1
  fi
}

fip_tx_begin_rollback() { # <root> <txid>
  local root="$1" txid="$2" active phase
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if [[ -e "$active/decision" || -L "$active/decision" ]]; then
    [[ "$(fip_tx_read_value "$active/decision" '^commit$')" == commit ]] || return 1
    fip_tx_error 'el commit ya fue decidido; el rollback esta prohibido'
    return 1
  fi
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" != committed ]] || return 1
  [[ "$phase" == rolling-back || "$phase" == rolled-back ]] \
    || fip_tx_set_phase "$root" "$txid" rolling-back
}

fip_tx_finish_fresh_directory() { # <root> <txid> <data> <template>
  local root="$1" txid="$2" data="$3" template="$4" active state
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_assert_paths_match "$active" "$data" "$template" || return 1
  state="$(fip_tx_read_value "$active/data-dir.meta" '^(absent|present)$')" || return 1
  [[ "$state" == absent ]] || return 0
  if [[ -d "$data" && ! -L "$data" ]]; then
    rmdir -- "$data" \
      || fip_tx_error 'el directorio nuevo contiene objetos no administrados; se conserva' \
      || return 1
  elif [[ -e "$data" || -L "$data" ]]; then
    fip_tx_error 'el directorio nuevo cambio de tipo durante el rollback'
    return 1
  fi
}

fip_tx_rollback_quiesce() { # <root> <txid>; ejecutar en TODOS los nodos
  fip_tx_begin_rollback "$1" "$2" || return 1
  [[ "$(fip_tx_phase "$1" "$2")" != rolled-back ]] || return 0
  fip_tx_remove_candidate "$1" "$2"
}

fip_tx_abort_unprepared() { # <root> <txid>; begin/prepare crash before mode/freeze
  local root="$1" txid="$2" active phase path
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" == preparing ]] || return 1
  for path in deployment.mode freeze.meta snapshot.complete quiesced.complete \
      old.cid candidate.cid template.installing.sha template.installed.sha; do
    [[ ! -e "$active/$path" && ! -L "$active/$path" ]] || return 1
  done
  fip_tx_set_phase "$root" "$txid" rolled-back
}

fip_tx_abort_pre_mutation() { # <root> <txid> <data> <template>; global barrier incomplete
  local root="$1" txid="$2" data="$3" template="$4" active original discovered
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  fip_tx_get_mode "$root" "$txid" >/dev/null || return 1
  # Puede existir snapshot/quiesced.complete en un subconjunto: mientras la
  # barrera N/N global no se complete, esos snapshots tampoco autorizan
  # mutaciones. Todos los nodos abortan entonces sin restaurar; el coordinador
  # debe elegir esta rama de forma global (v2 o legacy).
  [[ ! -e "$active/template.installing.sha" && ! -e "$active/template.installed.sha" ]] \
    || fip_tx_error 'el abort sin restaurar solo vale antes de publicar plantilla' \
    || return 1
  [[ ! -e "$active/candidate.cid" ]] \
    || fip_tx_error 'ya existe un candidato registrado; hace falta rollback completo' \
    || return 1
  if [[ -e "$active/old.original-name" ]]; then
    original="$(fip_tx_read_value "$active/old.original-name" \
      '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
    discovered="$(fip_tx_discover_candidate "$root" "$txid" "$original")" || return 1
    [[ "$discovered" == absent ]] \
      || fip_tx_error 'se descubrio un candidato; no se omitira la restauracion' \
      || return 1
  fi
  fip_tx_begin_rollback "$root" "$txid" || return 1
  fip_tx_restore_old_container "$root" "$txid" || return 1
  fip_tx_remove_freeze "$root" "$txid" "$data" "$template" || return 1
  fip_tx_finish_fresh_directory "$root" "$txid" "$data" "$template" || return 1
  fip_tx_set_phase "$root" "$txid" rolled-back
}

fip_tx_rollback_restore() { # <root> <txid> <data> <template>; TODOS los nodos
  [[ "$(fip_tx_phase "$1" "$2")" == rolling-back ]] || return 1
  fip_tx_restore_snapshot "$1" "$2" "$3" "$4"
}

fip_tx_rollback_restart() { # <root> <txid> <data> <template>; TODOS los nodos
  local root="$1" txid="$2" data="$3" template="$4"
  [[ "$(fip_tx_phase "$root" "$txid")" != rolled-back ]] || return 0
  [[ "$(fip_tx_phase "$root" "$txid")" == rolling-back ]] || return 1
  fip_tx_restore_old_container "$root" "$txid" || return 1
  fip_tx_remove_freeze "$root" "$txid" "$data" "$template" || return 1
  fip_tx_finish_fresh_directory "$root" "$txid" "$data" "$template" || return 1
  fip_tx_set_phase "$root" "$txid" rolled-back
}

fip_tx_rollback() { # helper nodo unico/pruebas; no usar secuencialmente en cluster
  [[ "$(fip_tx_phase "$1" "$2")" != rolled-back ]] || return 0
  fip_tx_rollback_quiesce "$1" "$2" || return 1
  fip_tx_rollback_restore "$1" "$2" "$3" "$4" || return 1
  fip_tx_rollback_restart "$1" "$2" "$3" "$4"
}

fip_tx_mark_verified() { # <root> <txid>
  local phase
  phase="$(fip_tx_phase "$1" "$2")" || return 1
  [[ "$phase" == prepared || "$phase" == mutating || "$phase" == verified ]] \
    || return 1
  [[ "$phase" == verified ]] || fip_tx_set_phase "$1" "$2" verified
}

fip_tx_decide_commit() { # <root> <txid>
  local root="$1" txid="$2" active phase decision
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  if [[ -e "$active/decision" ]]; then
    decision="$(fip_tx_read_value "$active/decision" '^commit$')" || return 1
    [[ "$decision" == commit ]] || return 1
    fip_tx_set_phase "$root" "$txid" commit-decided
    return
  fi
  phase="$(fip_tx_phase "$root" "$txid")" || return 1
  [[ "$phase" == verified ]] || fip_tx_error 'el commit exige fase verified' || return 1
  # La decision se hace durable antes de cambiar la fase. Recuperacion aplica
  # siempre "commit gana" si este fichero existe y es valido.
  fip_tx_atomic_text "$active/decision" 0600 commit || return 1
  fip_tx_set_phase "$root" "$txid" commit-decided
}

fip_tx_mark_committed() { # <root> <txid> <data> <template>
  local root="$1" txid="$2" data="$3" template="$4" active
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  [[ "$(fip_tx_read_value "$active/decision" '^commit$')" == commit ]] || return 1
  # committed implica que la plantilla candidata ya está publicada. Repetir la
  # instalación aquí cierra también una llamada remota fuera de orden; la
  # operación es idempotente y exige por sí misma commit-decided durable.
  fip_tx_install_template "$root" "$txid" "$data" "$template" || return 1
  fip_tx_remove_freeze "$root" "$txid" "$data" "$template" || return 1
  fip_tx_set_phase "$root" "$txid" committed
}

fip_tx_remove_old_after_commit() { # <root> <txid>
  local root="$1" txid="$2" active cid rollback observed running
  fip_tx_require_active "$root" "$txid" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  [[ "$(fip_tx_read_value "$active/decision" '^commit$')" == commit ]] || return 1
  [[ -e "$active/old.cid" ]] || return 0
  cid="$(fip_tx_read_value "$active/old.cid" '^(absent|[0-9a-f]{64})$')" || return 1
  [[ "$cid" != absent ]] || return 0
  docker inspect "$cid" >/dev/null 2>&1 || return 0
  rollback="$(fip_tx_read_value "$active/old.rollback-name" \
    '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')" || return 1
  observed="$(docker inspect --format '{{.Id}}' "$rollback")" || return 1
  [[ "$observed" == "$cid" ]] \
    || fip_tx_error 'el contenedor de rollback cambio de identidad' || return 1
  running="$(docker inspect --format '{{.State.Running}}' "$cid")" || return 1
  [[ "$running" == false ]] \
    || fip_tx_error 'el contenedor anterior sigue ejecutandose durante cleanup' \
    || return 1
  docker rm "$cid" >/dev/null || return 1
  ! docker inspect "$cid" >/dev/null 2>&1
}

fip_tx_assert_cleanup_inventory() { # <active journal directory>
  local active="$1" path base
  for path in "$active"/* "$active"/.[!.]* "$active"/..?*; do
    [[ -e "$path" || -L "$path" ]] || continue
    base="${path##*/}"
    case "$base" in
      .owner|.owner.tmp|.txid|.txid.tmp|phase|phase.tmp|\
      decision|decision.tmp|deployment.mode|deployment.mode.tmp|\
      snapshot.complete|snapshot.complete.tmp|paths.meta|paths.meta.tmp|\
      data-dir.meta|data-dir.meta.tmp|freeze.meta|freeze.meta.tmp|\
      template.candidate|template.candidate.meta|template.candidate.meta.tmp|\
      template.candidate.tmp|template.installing.sha|template.installing.sha.tmp|\
      template.installed.sha|template.installed.sha.tmp|\
      old.cid|old.cid.tmp|old.was-running|old.was-running.tmp|\
      old.original-name|old.original-name.tmp|old.rollback-name|old.rollback-name.tmp|\
      candidate.cid|candidate.cid.tmp|\
      snapshot.pool|snapshot.pool.meta|snapshot.pool-lock|snapshot.pool-lock.meta|\
      snapshot.pool.meta.tmp|snapshot.pool-lock.meta.tmp|\
      snapshot.security|snapshot.security.meta|\
      snapshot.security.meta.tmp|\
      snapshot.security-lock|snapshot.security-lock.meta|\
      snapshot.security-lock.meta.tmp|\
      snapshot.config|snapshot.config.meta|snapshot.protocol|snapshot.protocol.meta|\
      snapshot.config.meta.tmp|snapshot.protocol.meta.tmp|\
      snapshot.bootstrap-pool|snapshot.bootstrap-pool.meta|\
      snapshot.bootstrap-pool.meta.tmp|\
      snapshot.bootstrap-security|snapshot.bootstrap-security.meta|\
      snapshot.bootstrap-security.meta.tmp|\
      snapshot.template|snapshot.template.meta|snapshot.template.meta.tmp|\
      quiesced.complete|quiesced.complete.tmp|\
      quiesced.pool|quiesced.pool.meta|quiesced.pool-lock|quiesced.pool-lock.meta|\
      quiesced.pool.meta.tmp|quiesced.pool-lock.meta.tmp|\
      quiesced.security|quiesced.security.meta|\
      quiesced.security.meta.tmp|\
      quiesced.security-lock|quiesced.security-lock.meta|\
      quiesced.security-lock.meta.tmp|\
      quiesced.config|quiesced.config.meta|quiesced.protocol|quiesced.protocol.meta|\
      quiesced.config.meta.tmp|quiesced.protocol.meta.tmp|\
      quiesced.bootstrap-pool|quiesced.bootstrap-pool.meta|\
      quiesced.bootstrap-pool.meta.tmp|\
      quiesced.bootstrap-security|quiesced.bootstrap-security.meta|\
      quiesced.bootstrap-security.meta.tmp|\
      quiesced.template|quiesced.template.meta|quiesced.template.meta.tmp)
        [[ -f "$path" && ! -L "$path" ]] \
          || fip_tx_error "objeto de journal con tipo inesperado: $base" || return 1
        ;;
      *)
        fip_tx_error "objeto ajeno en el journal; no se limpiara: $base"
        return 1
        ;;
    esac
  done
}

fip_tx_cleanup() { # <root> <txid>; only committed or rolled-back
  local root="$1" txid="$2" active phase path key active_file marker marker_value
  local marker_txid
  local -a keys=(
    pool pool-lock security security-lock config protocol
    bootstrap-pool bootstrap-security template
  )
  local -a files=(
    snapshot.complete snapshot.complete.tmp quiesced.complete quiesced.complete.tmp
    paths.meta paths.meta.tmp data-dir.meta data-dir.meta.tmp
    deployment.mode deployment.mode.tmp freeze.meta freeze.meta.tmp
    template.candidate template.candidate.meta template.candidate.meta.tmp
    template.candidate.tmp template.installing.sha template.installing.sha.tmp
    template.installed.sha template.installed.sha.tmp
    old.cid old.cid.tmp old.was-running old.was-running.tmp
    old.original-name old.original-name.tmp old.rollback-name old.rollback-name.tmp
    candidate.cid candidate.cid.tmp decision decision.tmp
  )
  fip_tx_open_root "$root" || return 1
  fip_tx_repair_cleanup_tmp "$root" || return 1
  active="$(fip_tx_dir "$root" "$txid")"
  active_file="$root/active"
  marker="$root/cleanup"
  if [[ -e "$marker" || -L "$marker" ]]; then
    marker_value="$(fip_tx_read_value "$marker" \
      '^[0-9a-f]{32}\|(committed|rolled-back)$')" || return 1
    IFS='|' read -r marker_txid phase <<< "$marker_value"
    [[ "$marker_txid" == "$txid" ]] || return 1
  else
    fip_tx_require_active "$root" "$txid" || return 1
    phase="$(fip_tx_read_value "$active/phase" \
      '^(committed|rolled-back)$')" || return 1
    [[ "$phase" == committed || "$phase" == rolled-back ]] \
      || fip_tx_error 'solo una transaccion terminada puede limpiarse' || return 1
    fip_tx_assert_cleanup_inventory "$active" || return 1
    if [[ "$phase" == committed ]]; then
      fip_tx_remove_old_after_commit "$root" "$txid" || return 1
    fi
    # La evidencia root-level se publica antes de retirar un solo fichero del
    # journal. Discovery siempre puede reanudar aunque phase/.txid ya no existan.
    fip_tx_atomic_text "$marker" 0600 "$txid|$phase" || return 1
  fi

  if [[ ! -e "$active" && ! -L "$active" ]]; then
    [[ ! -e "$active_file" && ! -L "$active_file" ]] || return 1
    fip_tx_remove_known_file "$marker" 600 || return 1
    fip_tx_sync_dir "$root"
    return
  fi
  [[ -d "$active" && ! -L "$active" && "$(readlink -f -- "$active")" == "$active" \
      && "$(stat -c '%u:%g:%a' -- "$active")" == 0:0:700 ]] || return 1
  fip_tx_assert_cleanup_inventory "$active" || return 1

  for key in "${keys[@]}"; do
    files+=("snapshot.$key" "snapshot.$key.meta" \
      "snapshot.$key.meta.tmp" "quiesced.$key" "quiesced.$key.meta" \
      "quiesced.$key.meta.tmp")
  done
  for path in "${files[@]}"; do
    fip_tx_remove_known_file "$active/$path" 600 || return 1
  done
  if [[ -e "$active_file" || -L "$active_file" ]]; then
    fip_tx_regular_root_file "$active_file" 600 || return 1
    [[ "$(fip_tx_read_value "$active_file" '^[0-9a-f]{32}$')" == "$txid" ]] \
      || return 1
    rm -f -- "$active_file" || return 1
    fip_tx_sync_dir "$root" || return 1
  fi
  for path in phase.tmp .txid.tmp .owner.tmp phase .txid .owner; do
    fip_tx_remove_known_file "$active/$path" 600 || return 1
  done
  rmdir -- "$active" \
    || fip_tx_error 'el journal contiene objetos no reconocidos; no se eliminaran' \
    || return 1
  fip_tx_sync_dir "$root" || return 1
  fip_tx_remove_known_file "$marker" 600 || return 1
  fip_tx_sync_dir "$root"
}
