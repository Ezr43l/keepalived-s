#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ "$(id -u)" != 0 ]]; then
  command -v docker >/dev/null 2>&1 || {
    echo 'Docker es necesario para probar propietarios root:root.' >&2
    exit 1
  }
  docker run --rm \
    -v "$repo_root:/repo:ro" \
    bash:5.3@sha256:a19c811ee9e97fa8a080001d82b8e0ded303f0795cffdb1cbd162731bc8ce208 \
    bash /repo/docker/keepalived/tests/test-deploy-transaction.sh
  exit
fi

# shellcheck disable=SC1091
source "$repo_root/deploy-transaction-lib.sh"

test_root="$(mktemp -d)"
cleanup_test_root() {
  find "$test_root" -depth -delete
}
trap cleanup_test_root EXIT

mkdir -p -- "$test_root/bin" "$test_root/docker-state/containers"
export MOCK_DOCKER_DIR="$test_root/docker-state"
export MOCK_DOCKER_LOG="$test_root/docker.log"

cat > "$test_root/bin/docker" <<'MOCK_DOCKER'
#!/usr/bin/env bash
set -euo pipefail

state="$MOCK_DOCKER_DIR"
log="$MOCK_DOCKER_LOG"
command_name="${1:-}"; shift || true

lookup() {
  local ref="$1" directory
  for directory in "$state"/containers/*; do
    [[ -d "$directory" ]] || continue
    if [[ "$(< "$directory/cid")" == "$ref" || "$(< "$directory/name")" == "$ref" ]]; then
      printf '%s\n' "$directory"
      return 0
    fi
  done
  return 1
}

fail_once() {
  local marker="$state/fail-$1"
  if [[ -f "$marker" ]]; then
    rm -f -- "$marker"
    printf 'FAIL:%s\n' "$1" >> "$log"
    return 0
  fi
  return 1
}

case "$command_name" in
  inspect)
    format=""
    if [[ "${1:-}" == --format ]]; then
      format="$2"; shift 2
    fi
    ref="${1:-}"
    directory="$(lookup "$ref")" || exit 1
    cid="$(< "$directory/cid")"
    running="$(< "$directory/running")"
    paused="$(< "$directory/paused")"
    case "$format" in
      '') ;;
      *io.ezr43l.deploy-transaction*)
        printf '%s|%s|%s\n' "$cid" "$(< "$directory/label-tx")" \
          "$(< "$directory/label-role")"
        ;;
      *State.Running*State.Paused*) printf '%s|%s|%s\n' "$cid" "$running" "$paused" ;;
      '{{.State.Running}}') printf '%s\n' "$running" ;;
      '{{.Id}}') printf '%s\n' "$cid" ;;
      *) echo "formato inspect no simulado: $format" >&2; exit 91 ;;
    esac
    ;;
  kill)
    [[ "${1:-}" == --signal=TERM ]] || {
      echo 'el mock solo admite TERM' >&2
      exit 92
    }
    shift
    directory="$(lookup "$1")" || exit 1
    printf 'kill:TERM:%s\n' "$(< "$directory/cid")" >> "$log"
    if [[ ! -f "$state/term-stuck" ]]; then
      printf '%s\n' false > "$directory/running"
    fi
    ;;
  unpause)
    directory="$(lookup "$1")" || exit 1
    printf 'unpause:%s\n' "$(< "$directory/cid")" >> "$log"
    printf '%s\n' false > "$directory/paused"
    ;;
  rename)
    fail_once rename && exit 55
    directory="$(lookup "$1")" || exit 1
    printf 'rename:%s:%s\n' "$(< "$directory/cid")" "$2" >> "$log"
    printf '%s\n' "$2" > "$directory/name"
    ;;
  start)
    directory="$(lookup "$1")" || exit 1
    printf 'start:%s\n' "$(< "$directory/cid")" >> "$log"
    printf '%s\n' true > "$directory/running"
    printf '%s\n' false > "$directory/paused"
    printf '%s\n' "$(< "$directory/cid")"
    ;;
  rm)
    fail_once rm && exit 56
    directory="$(lookup "$1")" || exit 1
    [[ "$(< "$directory/running")" == false ]] || exit 57
    printf 'rm:%s\n' "$(< "$directory/cid")" >> "$log"
    for file in cid name running paused label-tx label-role; do
      rm -f -- "$directory/$file"
    done
    rmdir -- "$directory"
    printf '%s\n' "$1"
    ;;
  *)
    echo "comando Docker no simulado: $command_name" >&2
    exit 90
    ;;
esac
MOCK_DOCKER
chmod 0755 -- "$test_root/bin/docker"
export PATH="$test_root/bin:$PATH"

create_container() { # <slot> <name> <cid> <running> <paused> <tx> <role>
  local slot="$1" name="$2" cid="$3" running="$4" paused="$5"
  local tx="$6" role="$7" directory="$MOCK_DOCKER_DIR/containers/$slot"
  mkdir -- "$directory"
  printf '%s\n' "$cid" > "$directory/cid"
  printf '%s\n' "$name" > "$directory/name"
  printf '%s\n' "$running" > "$directory/running"
  printf '%s\n' "$paused" > "$directory/paused"
  printf '%s\n' "$tx" > "$directory/label-tx"
  printf '%s\n' "$role" > "$directory/label-role"
}

remove_container_fixture() { # <slot>; test-only exact cleanup
  local directory="$MOCK_DOCKER_DIR/containers/$1" file
  [[ -d "$directory" ]] || return 0
  for file in cid name running paused label-tx label-role; do
    rm -f -- "$directory/$file"
  done
  rmdir -- "$directory"
}

assert_file_text() { # <path> <single line>
  local path="$1" expected="$2" actual
  IFS= read -r actual < "$path"
  [[ "$actual" == "$expected" ]]
  [[ "$(wc -l < "$path")" == 1 ]]
}

state_names=(
  pool.json pool.json.lock security.json security.json.lock keepalived.conf
  .cluster-protocol-v2
)

# Rutas dedicadas y normalizadas.
mkdir -p -- "$test_root/path-check/data" "$test_root/path-check/templates"
chmod 0700 -- "$test_root/path-check/data"
if fip_tx_validate_paths relative/path \
    "$test_root/path-check/templates/template.xml" "$test_root/path-check/tx"; then
  echo 'se acepto una ruta relativa' >&2
  exit 1
fi
if fip_tx_validate_paths "$test_root/path-check/data" \
    "$test_root/path-check/templates/template.xml" "$test_root/path-check/data/tx"; then
  echo 'se acepto el journal dentro de /datos' >&2
  exit 1
fi
if fip_tx_validate_paths "$test_root/path-check/data" \
    "$test_root/path-check/templates/template.xml" /boot/fip-transactions; then
  echo 'se acepto un journal bajo /boot' >&2
  exit 1
fi

# Publicacion crash-consistent de active: un staging parcial nunca se expone y
# el hardlink temporal que pudiera quedar tras publicar active se repara.
begin_crash_root="$test_root/begin-crash/transactions"
begin_crash_txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir -p -- "$test_root/begin-crash"
fip_tx_open_root "$begin_crash_root"
mkdir -- "$begin_crash_root/.prepare-$begin_crash_txid"
chmod 0700 -- "$begin_crash_root/.prepare-$begin_crash_txid"
printf '%s\n' partial > "$begin_crash_root/.prepare-$begin_crash_txid/phase.tmp"
chmod 0600 -- "$begin_crash_root/.prepare-$begin_crash_txid/phase.tmp"
fip_tx_begin "$begin_crash_root" "$begin_crash_txid"
[[ "$(fip_tx_discover "$begin_crash_root")" == \
  "txid=$begin_crash_txid;phase=preparing;decision=none" ]]
ln -- "$begin_crash_root/active" \
  "$begin_crash_root/.active-$begin_crash_txid.tmp"
[[ "$(stat -c %h "$begin_crash_root/active")" == 2 ]]
[[ "$(fip_tx_discover "$begin_crash_root")" == \
  "txid=$begin_crash_txid;phase=preparing;decision=none" ]]
[[ "$(stat -c %h "$begin_crash_root/active")" == 1 \
    && ! -e "$begin_crash_root/.active-$begin_crash_txid.tmp" ]]
fip_tx_set_phase "$begin_crash_root" "$begin_crash_txid" rolled-back
fip_tx_cleanup "$begin_crash_root" "$begin_crash_txid"

# Una invocación nueva con otro TXID debe recolectar staging incompleto, pero
# descubrir/publicar un journal completo huérfano y negarse a adelantarlo.
begin_new_root="$test_root/begin-new/transactions"
begin_staging_old=abababababababababababababababab
begin_staging_new=acacacacacacacacacacacacacacacac
mkdir -p -- "$test_root/begin-new"
fip_tx_open_root "$begin_new_root"
mkdir -- "$begin_new_root/.prepare-$begin_staging_old"
chmod 0700 -- "$begin_new_root/.prepare-$begin_staging_old"
printf '%s\n' partial > "$begin_new_root/.prepare-$begin_staging_old/phase.tmp"
chmod 0600 -- "$begin_new_root/.prepare-$begin_staging_old/phase.tmp"
fip_tx_begin "$begin_new_root" "$begin_staging_new"
[[ ! -e "$begin_new_root/.prepare-$begin_staging_old" ]]
[[ "$(fip_tx_discover "$begin_new_root")" == \
  "txid=$begin_staging_new;phase=preparing;decision=none" ]]
fip_tx_abort_unprepared "$begin_new_root" "$begin_staging_new"
fip_tx_cleanup "$begin_new_root" "$begin_staging_new"

begin_orphan_root="$test_root/begin-orphan/transactions"
begin_orphan_old=adadadadadadadadadadadadadadadad
begin_orphan_new=aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae
mkdir -p -- "$test_root/begin-orphan"
fip_tx_begin "$begin_orphan_root" "$begin_orphan_old"
rm -f -- "$begin_orphan_root/active"
if fip_tx_begin "$begin_orphan_root" "$begin_orphan_new"; then
  echo 'una nueva invocación ignoró un journal completo no publicado' >&2
  exit 1
fi
[[ "$(fip_tx_discover "$begin_orphan_root")" == \
  "txid=$begin_orphan_old;phase=preparing;decision=none" ]]
fip_tx_abort_unprepared "$begin_orphan_root" "$begin_orphan_old"
fip_tx_cleanup "$begin_orphan_root" "$begin_orphan_old"

begin_tmp_root="$test_root/begin-active-tmp/transactions"
begin_tmp_txid=afafafafafafafafafafafafafafafaf
mkdir -p -- "$test_root/begin-active-tmp"
fip_tx_begin "$begin_tmp_root" "$begin_tmp_txid"
mv -- "$begin_tmp_root/active" "$begin_tmp_root/.active-$begin_tmp_txid.tmp"
[[ "$(fip_tx_discover "$begin_tmp_root")" == \
  "txid=$begin_tmp_txid;phase=preparing;decision=none" ]]
[[ -f "$begin_tmp_root/active" \
    && ! -e "$begin_tmp_root/.active-$begin_tmp_txid.tmp" ]]
fip_tx_abort_unprepared "$begin_tmp_root" "$begin_tmp_txid"
fip_tx_cleanup "$begin_tmp_root" "$begin_tmp_txid"

# Cleanup publica primero una evidencia root-level. Se simulan los cortes tras
# marker, payload, active, metadatos y rmdir: discovery/retry debe cerrar todos.
for cleanup_cut in marker payload active metadata rmdir; do
  case "$cleanup_cut" in
    marker) cleanup_txid=51515151515151515151515151515151 ;;
    payload) cleanup_txid=52525252525252525252525252525252 ;;
    active) cleanup_txid=53535353535353535353535353535353 ;;
    metadata) cleanup_txid=54545454545454545454545454545454 ;;
    rmdir) cleanup_txid=56565656565656565656565656565656 ;;
  esac
  cleanup_root="$test_root/cleanup-$cleanup_cut/transactions"
  mkdir -p -- "$test_root/cleanup-$cleanup_cut"
  fip_tx_begin "$cleanup_root" "$cleanup_txid"
  cleanup_dir="$(fip_tx_dir "$cleanup_root" "$cleanup_txid")"
  fip_tx_atomic_text "$cleanup_dir/data-dir.meta" 0600 absent
  fip_tx_set_phase "$cleanup_root" "$cleanup_txid" rolled-back
  fip_tx_atomic_text "$cleanup_root/cleanup" 0600 "$cleanup_txid|rolled-back"
  if [[ "$cleanup_cut" != marker ]]; then
    rm -f -- "$cleanup_dir/data-dir.meta"
  fi
  if [[ "$cleanup_cut" == active || "$cleanup_cut" == metadata \
      || "$cleanup_cut" == rmdir ]]; then
    rm -f -- "$cleanup_root/active"
  fi
  if [[ "$cleanup_cut" == metadata || "$cleanup_cut" == rmdir ]]; then
    rm -f -- "$cleanup_dir/phase" "$cleanup_dir/.txid" "$cleanup_dir/.owner"
  fi
  if [[ "$cleanup_cut" == rmdir ]]; then
    rmdir -- "$cleanup_dir"
  fi
  [[ "$(fip_tx_discover "$cleanup_root")" == \
    "txid=$cleanup_txid;phase=rolled-back;decision=none" ]]
  [[ "$(fip_tx_recovery_action "$cleanup_root")" == "cleanup:$cleanup_txid" ]]
  fip_tx_cleanup "$cleanup_root" "$cleanup_txid"
  [[ "$(fip_tx_discover "$cleanup_root")" == none ]]
done

# La publicacion atomica del marker tambien se reanuda si el proceso cae antes
# o despues del rename. Un temporal truncado propio se descarta solo cuando el
# active acredita la misma fase terminal.
for cleanup_tmp_cut in valid incomplete after-marker; do
  case "$cleanup_tmp_cut" in
    valid) cleanup_tmp_txid=61616161616161616161616161616161 ;;
    incomplete) cleanup_tmp_txid=62626262626262626262626262626262 ;;
    after-marker) cleanup_tmp_txid=63636363636363636363636363636363 ;;
  esac
  cleanup_tmp_root="$test_root/cleanup-tmp-$cleanup_tmp_cut/transactions"
  mkdir -p -- "$test_root/cleanup-tmp-$cleanup_tmp_cut"
  fip_tx_begin "$cleanup_tmp_root" "$cleanup_tmp_txid"
  fip_tx_set_phase "$cleanup_tmp_root" "$cleanup_tmp_txid" rolled-back
  if [[ "$cleanup_tmp_cut" == after-marker ]]; then
    fip_tx_atomic_text "$cleanup_tmp_root/cleanup" 0600 \
      "$cleanup_tmp_txid|rolled-back"
  fi
  if [[ "$cleanup_tmp_cut" == incomplete ]]; then
    (umask 077; printf '%s' "$cleanup_tmp_txid|" \
      > "$cleanup_tmp_root/cleanup.tmp")
  else
    (umask 077; printf '%s\n' "$cleanup_tmp_txid|rolled-back" \
      > "$cleanup_tmp_root/cleanup.tmp")
  fi
  chown 0:0 -- "$cleanup_tmp_root/cleanup.tmp"
  chmod 0600 -- "$cleanup_tmp_root/cleanup.tmp"
  [[ "$(fip_tx_discover "$cleanup_tmp_root")" == \
    "txid=$cleanup_tmp_txid;phase=rolled-back;decision=none" ]]
  [[ ! -e "$cleanup_tmp_root/cleanup.tmp" ]]
  fip_tx_cleanup "$cleanup_tmp_root" "$cleanup_tmp_txid"
  [[ "$(fip_tx_discover "$cleanup_tmp_root")" == none ]]
done

# Solo los nombres temporales exactos de operaciones del journal son propios.
# Un nombre parecido pero ajeno bloquea todo borrado hasta intervencion explicita.
cleanup_atomic_root="$test_root/cleanup-atomic/transactions"
cleanup_atomic_txid=64646464646464646464646464646464
mkdir -p -- "$test_root/cleanup-atomic"
fip_tx_begin "$cleanup_atomic_root" "$cleanup_atomic_txid"
cleanup_atomic_dir="$(fip_tx_dir "$cleanup_atomic_root" "$cleanup_atomic_txid")"
fip_tx_set_phase "$cleanup_atomic_root" "$cleanup_atomic_txid" rolled-back
printf '%s\n' commit > "$cleanup_atomic_dir/decision.tmp"
printf '%s\n' partial > "$cleanup_atomic_dir/snapshot.pool.meta.tmp"
printf '%s\n' foreign > "$cleanup_atomic_dir/snapshot.foreign.meta.tmp"
chown 0:0 -- "$cleanup_atomic_dir/decision.tmp" \
  "$cleanup_atomic_dir/snapshot.pool.meta.tmp" \
  "$cleanup_atomic_dir/snapshot.foreign.meta.tmp"
chmod 0600 -- "$cleanup_atomic_dir/decision.tmp" \
  "$cleanup_atomic_dir/snapshot.pool.meta.tmp" \
  "$cleanup_atomic_dir/snapshot.foreign.meta.tmp"
if fip_tx_cleanup "$cleanup_atomic_root" "$cleanup_atomic_txid"; then
  echo 'cleanup acepto un temporal no reconocido' >&2
  exit 1
fi
[[ -f "$cleanup_atomic_dir/decision.tmp" \
    && -f "$cleanup_atomic_dir/snapshot.pool.meta.tmp" \
    && -f "$cleanup_atomic_dir/snapshot.foreign.meta.tmp" ]]
rm -f -- "$cleanup_atomic_dir/snapshot.foreign.meta.tmp"
fip_tx_cleanup "$cleanup_atomic_root" "$cleanup_atomic_txid"
[[ "$(fip_tx_discover "$cleanup_atomic_root")" == none ]]

# Reanudacion de los dos cortes de instalacion del marker: meta antes de link y
# link antes de retirar el temporal (nlink=2).
freeze_crash="$test_root/freeze-crash"
freeze_data="$freeze_crash/data"
freeze_templates="$freeze_crash/templates"
freeze_template="$freeze_templates/template.xml"
freeze_root="$freeze_crash/transactions"
freeze_txid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
mkdir -p -- "$freeze_data" "$freeze_templates"
chmod 0700 -- "$freeze_data"
fip_tx_begin "$freeze_root" "$freeze_txid"
fip_tx_prepare_paths "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
fip_tx_set_mode "$freeze_root" "$freeze_txid" v2
[[ "$(fip_tx_get_mode "$freeze_root" "$freeze_txid")" == v2 ]]
[[ "$(fip_tx_baseline "$freeze_root" "$freeze_txid")" == none ]]
if fip_tx_set_mode "$freeze_root" "$freeze_txid" legacy; then
  echo 'se permitio cambiar el modo durable de la transaccion' >&2
  exit 1
fi
fip_tx_install_freeze "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
freeze_tmp="$freeze_data/.deploy-freeze.$freeze_txid.tmp"
ln -- "$freeze_data/.deploy-freeze" "$freeze_tmp"
[[ "$(stat -c %h "$freeze_data/.deploy-freeze")" == 2 ]]
fip_tx_install_freeze "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
[[ ! -e "$freeze_tmp" && "$(stat -c %h "$freeze_data/.deploy-freeze")" == 1 ]]
ln -- "$freeze_data/.deploy-freeze" "$freeze_tmp"
rm -f -- "$freeze_data/.deploy-freeze"
fip_tx_install_freeze "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
[[ -f "$freeze_data/.deploy-freeze" && ! -e "$freeze_tmp" ]]
fip_tx_snapshot "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
[[ "$(fip_tx_baseline "$freeze_root" "$freeze_txid")" == snapshot ]]
fip_tx_begin_rollback "$freeze_root" "$freeze_txid"
fip_tx_rollback_restore "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
fip_tx_rollback_restart "$freeze_root" "$freeze_txid" "$freeze_data" "$freeze_template"
fip_tx_cleanup "$freeze_root" "$freeze_txid"

# Recovery de plantilla en los dos cortes posteriores al rename: con solo
# installing.sha se completa installed.sha; con installed.sha el reintento es
# idempotente y no exige que siga presente la plantilla original.
template_crash="$test_root/template-crash"
template_crash_data="$template_crash/data"
template_crash_templates="$template_crash/templates"
template_crash_file="$template_crash_templates/template.xml"
template_crash_root="$template_crash/transactions"
template_crash_txid=cccccccccccccccccccccccccccccccc
mkdir -p -- "$template_crash_data" "$template_crash_templates"
chmod 0700 -- "$template_crash_data"
printf '%s\n' original > "$template_crash_file"
chmod 0600 -- "$template_crash_file"
fip_tx_begin "$template_crash_root" "$template_crash_txid"
template_crash_dir="$(fip_tx_dir "$template_crash_root" "$template_crash_txid")"
fip_tx_prepare_paths "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
fip_tx_set_mode "$template_crash_root" "$template_crash_txid" v2
fip_tx_install_freeze "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
fip_tx_snapshot "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
printf '%s\n' candidate | fip_tx_stage_template "$template_crash_root" \
  "$template_crash_txid" "$template_crash_data" "$template_crash_file"
if fip_tx_install_template "$template_crash_root" "$template_crash_txid" \
    "$template_crash_data" "$template_crash_file"; then
  echo 'se publico la plantilla antes de una decision commit durable' >&2
  exit 1
fi
assert_file_text "$template_crash_file" original
fip_tx_mark_verified "$template_crash_root" "$template_crash_txid"
fip_tx_decide_commit "$template_crash_root" "$template_crash_txid"
template_candidate_meta="$(fip_tx_read_value \
  "$template_crash_dir/template.candidate.meta" '^[0-9]{1,7}\|[0-9a-f]{64}$')"
IFS='|' read -r template_candidate_bytes template_candidate_sha \
  <<< "$template_candidate_meta"
fip_tx_atomic_text "$template_crash_dir/template.installing.sha" 0600 \
  "$template_candidate_sha"
cp -- "$template_crash_dir/template.candidate" "$template_crash_file"
chown 0:0 -- "$template_crash_file"
chmod 0600 -- "$template_crash_file"
[[ "$(stat -c %s -- "$template_crash_file")" == "$template_candidate_bytes" ]]
fip_tx_install_template "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
[[ "$(fip_tx_read_value "$template_crash_dir/template.installed.sha" \
  '^[0-9a-f]{64}$')" == "$template_candidate_sha" ]]
fip_tx_install_template "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
assert_file_text "$template_crash_file" candidate
fip_tx_mark_committed "$template_crash_root" "$template_crash_txid" \
  "$template_crash_data" "$template_crash_file"
fip_tx_cleanup "$template_crash_root" "$template_crash_txid"

# Caso existente: snapshot, TERM sin KILL, rename, candidato y rollback exacto.
case_one="$test_root/case-one"
data="$case_one/data"
templates="$case_one/templates"
template="$templates/my-Keepalived.xml"
tx_root="$case_one/transactions"
txid=11111111111111111111111111111111
old_cid="$(printf '%064x' 1)"
candidate_cid="$(printf '%064x' 2)"
mkdir -p -- "$data" "$templates"
chmod 0700 -- "$data"
for name in "${state_names[@]}"; do
  printf 'original:%s\n' "$name" > "$data/$name"
  chmod 0600 -- "$data/$name"
done
printf '%s\n' '<Container>original</Container>' > "$template"
chmod 0600 -- "$template"
before_state="$(sha256sum "$data"/pool.json "$data"/pool.json.lock \
  "$data"/security.json "$data"/security.json.lock \
  "$data"/keepalived.conf "$data"/.cluster-protocol-v2)"
before_template="$(sha256sum "$template")"

create_container old Keepalived "$old_cid" true true '' old
fip_tx_begin "$tx_root" "$txid"
tx_dir="$(fip_tx_dir "$tx_root" "$txid")"
fip_tx_prepare_paths "$tx_root" "$txid" "$data" "$template"
fip_tx_set_mode "$tx_root" "$txid" legacy
fip_tx_install_freeze "$tx_root" "$txid" "$data" "$template"
fip_tx_snapshot "$tx_root" "$txid" "$data" "$template"
[[ "$(fip_tx_baseline "$tx_root" "$txid")" == snapshot ]]
assert_file_text "$data/.deploy-freeze" deploy-freeze-v1
[[ "$(stat -c '%u:%g:%a:%h' "$data/.deploy-freeze")" == 0:0:600:1 ]]

fip_tx_preserve_container "$tx_root" "$txid" Keepalived fip-rb-one
fip_tx_snapshot_quiesced "$tx_root" "$txid" "$data" "$template"
[[ "$(fip_tx_baseline "$tx_root" "$txid")" == quiesced ]]
[[ "$(docker inspect --format '{{.Id}}' fip-rb-one)" == "$old_cid" ]]
grep -Fq "kill:TERM:$old_cid" "$MOCK_DOCKER_LOG"
grep -Fq "unpause:$old_cid" "$MOCK_DOCKER_LOG"
[[ "$(grep -n -F "unpause:$old_cid" "$MOCK_DOCKER_LOG" | cut -d: -f1)" \
    -lt "$(grep -n -F "kill:TERM:$old_cid" "$MOCK_DOCKER_LOG" | cut -d: -f1)" ]]

printf '%s\n' '<Container>candidate</Container>' \
  | fip_tx_stage_template "$tx_root" "$txid" "$data" "$template"
if fip_tx_install_template "$tx_root" "$txid" "$data" "$template"; then
  echo 'se publico una plantilla staged en la rama rollback' >&2
  exit 1
fi
assert_file_text "$template" '<Container>original</Container>'

for name in "${state_names[@]}"; do
  printf 'candidate:%s\n' "$name" > "$data/$name"
  chmod 0600 -- "$data/$name"
done
printf '%s\n' fresh-install-v1 > "$data/.bootstrap-pool"
printf '%s\n' fresh-install-v1 > "$data/.bootstrap-security"
chmod 0600 -- "$data/.bootstrap-pool" "$data/.bootstrap-security"
create_container candidate Keepalived "$candidate_cid" true false "$txid" candidate
[[ ! -e "$tx_dir/candidate.cid" ]]
[[ "$(fip_tx_discover_candidate "$tx_root" "$txid" Keepalived)" == "$candidate_cid" ]]
[[ -f "$tx_dir/candidate.cid" ]]
fip_tx_record_candidate "$tx_root" "$txid" Keepalived "$candidate_cid"

fip_tx_rollback "$tx_root" "$txid" "$data" "$template"
[[ "$before_state" == "$(sha256sum "$data"/pool.json "$data"/pool.json.lock \
  "$data"/security.json "$data"/security.json.lock \
  "$data"/keepalived.conf "$data"/.cluster-protocol-v2)" ]]
[[ "$before_template" == "$(sha256sum "$template")" ]]
[[ ! -e "$data/.bootstrap-pool" && ! -e "$data/.bootstrap-security" \
    && ! -e "$data/.deploy-freeze" ]]
[[ "$(docker inspect --format '{{.Id}}' Keepalived)" == "$old_cid" ]]
[[ "$(docker inspect --format '{{.State.Running}}' Keepalived)" == true ]]
if docker inspect "$candidate_cid" >/dev/null 2>&1; then
  echo 'el candidato sobrevivio al rollback' >&2
  exit 1
fi
[[ "$(fip_tx_phase "$tx_root" "$txid")" == rolled-back ]]
fip_tx_rollback "$tx_root" "$txid" "$data" "$template"

# Un objeto ajeno bloquea cleanup antes de que se borre el journal.
printf '%s\n' sentinel > "$tx_dir/foreign-object"
chmod 0600 -- "$tx_dir/foreign-object"
if fip_tx_cleanup "$tx_root" "$txid"; then
  echo 'cleanup elimino o acepto un objeto ajeno' >&2
  exit 1
fi
[[ -f "$tx_root/active" && -f "$tx_dir/.txid" && -f "$tx_dir/foreign-object" ]]
rm -f -- "$tx_dir/foreign-object"
fip_tx_cleanup "$tx_root" "$txid"
[[ ! -e "$tx_root/active" ]]
remove_container_fixture old

# Fresh install parcial: un fallo inyectado en docker rm deja journal durable;
# el segundo rollback termina y devuelve datos/plantilla a ausencia exacta.
case_two="$test_root/case-two"
data_two="$case_two/data"
templates_two="$case_two/templates"
template_two="$templates_two/my-Keepalived.xml"
tx_root_two="$case_two/transactions"
txid_two=22222222222222222222222222222222
candidate_two_cid="$(printf '%064x' 3)"
mkdir -p -- "$case_two" "$templates_two"
fip_tx_begin "$tx_root_two" "$txid_two"
fip_tx_prepare_paths "$tx_root_two" "$txid_two" "$data_two" "$template_two"
fip_tx_set_mode "$tx_root_two" "$txid_two" v2
fip_tx_install_freeze "$tx_root_two" "$txid_two" "$data_two" "$template_two"
fip_tx_snapshot "$tx_root_two" "$txid_two" "$data_two" "$template_two"
fip_tx_preserve_container "$tx_root_two" "$txid_two" Keepalived fip-rb-two
for name in pool.json pool.json.lock security.json security.json.lock keepalived.conf \
    .cluster-protocol-v2 .bootstrap-pool .bootstrap-security; do
  printf 'partial:%s\n' "$name" > "$data_two/$name"
  chmod 0600 -- "$data_two/$name"
done
printf '%s\n' '<Container>partial</Container>' \
  | fip_tx_stage_template "$tx_root_two" "$txid_two" "$data_two" "$template_two"
create_container candidate-two Keepalived "$candidate_two_cid" true false \
  "$txid_two" candidate
fip_tx_record_candidate "$tx_root_two" "$txid_two" Keepalived "$candidate_two_cid"
printf '%s\n' fail > "$MOCK_DOCKER_DIR/fail-rm"
if fip_tx_rollback_quiesce "$tx_root_two" "$txid_two"; then
  echo 'el fallo inyectado en docker rm no interrumpio rollback' >&2
  exit 1
fi
[[ "$(fip_tx_phase "$tx_root_two" "$txid_two")" == rolling-back ]]
[[ -f "$tx_root_two/active" ]]
fip_tx_rollback_quiesce "$tx_root_two" "$txid_two"
fip_tx_rollback_restore "$tx_root_two" "$txid_two" "$data_two" "$template_two"
fip_tx_rollback_restart "$tx_root_two" "$txid_two" "$data_two" "$template_two"
[[ ! -e "$data_two" && ! -e "$template_two" ]]
if docker inspect "$candidate_two_cid" >/dev/null 2>&1; then
  echo 'el candidato fresh sobrevivio al rollback' >&2
  exit 1
fi
fip_tx_cleanup "$tx_root_two" "$txid_two"

# CID/labels: una sustitucion ajena jamas se borra.
case_three="$test_root/case-three"
data_three="$case_three/data"
templates_three="$case_three/templates"
template_three="$templates_three/my-Keepalived.xml"
tx_root_three="$case_three/transactions"
txid_three=33333333333333333333333333333333
candidate_three_cid="$(printf '%064x' 4)"
mkdir -p -- "$data_three" "$templates_three"
chmod 0700 -- "$data_three"
printf '%s\n' original > "$data_three/pool.json"
chmod 0600 -- "$data_three/pool.json"
fip_tx_begin "$tx_root_three" "$txid_three"
fip_tx_prepare_paths "$tx_root_three" "$txid_three" "$data_three" "$template_three"
fip_tx_set_mode "$tx_root_three" "$txid_three" v2
fip_tx_install_freeze "$tx_root_three" "$txid_three" "$data_three" "$template_three"
fip_tx_snapshot "$tx_root_three" "$txid_three" "$data_three" "$template_three"
fip_tx_preserve_container "$tx_root_three" "$txid_three" Keepalived fip-rb-three
create_container candidate-three Keepalived "$candidate_three_cid" true false \
  "$txid_three" candidate
fip_tx_record_candidate "$tx_root_three" "$txid_three" Keepalived "$candidate_three_cid"
printf '%s\n' foreign-tx > "$MOCK_DOCKER_DIR/containers/candidate-three/label-tx"
fip_tx_begin_rollback "$tx_root_three" "$txid_three"
if fip_tx_remove_candidate "$tx_root_three" "$txid_three"; then
  echo 'se elimino un candidato cuya etiqueta de transaccion cambio' >&2
  exit 1
fi
docker inspect "$candidate_three_cid" >/dev/null
printf '%s\n' "$txid_three" > "$MOCK_DOCKER_DIR/containers/candidate-three/label-tx"
fip_tx_rollback "$tx_root_three" "$txid_three" "$data_three" "$template_three"
fip_tx_cleanup "$tx_root_three" "$txid_three"

# Commit gana: despues de la decision no hay rollback y cleanup retira solo el
# contenedor anterior preservado, dejando el candidato activo.
case_four="$test_root/case-four"
data_four="$case_four/data"
templates_four="$case_four/templates"
template_four="$templates_four/my-Keepalived.xml"
tx_root_four="$case_four/transactions"
txid_four=44444444444444444444444444444444
old_four_cid="$(printf '%064x' 5)"
candidate_four_cid="$(printf '%064x' 6)"
mkdir -p -- "$data_four" "$templates_four"
chmod 0700 -- "$data_four"
printf '%s\n' original > "$data_four/pool.json"
chmod 0600 -- "$data_four/pool.json"
create_container old-four Keepalived "$old_four_cid" true false '' old
fip_tx_begin "$tx_root_four" "$txid_four"
fip_tx_prepare_paths "$tx_root_four" "$txid_four" "$data_four" "$template_four"
fip_tx_set_mode "$tx_root_four" "$txid_four" v2
fip_tx_install_freeze "$tx_root_four" "$txid_four" "$data_four" "$template_four"
fip_tx_snapshot "$tx_root_four" "$txid_four" "$data_four" "$template_four"
fip_tx_preserve_container "$tx_root_four" "$txid_four" Keepalived fip-rb-four
printf '%s\n' '<Container>committed</Container>' \
  | fip_tx_stage_template "$tx_root_four" "$txid_four" "$data_four" "$template_four"
create_container candidate-four Keepalived "$candidate_four_cid" true false \
  "$txid_four" candidate
fip_tx_record_candidate "$tx_root_four" "$txid_four" Keepalived "$candidate_four_cid"
fip_tx_mark_verified "$tx_root_four" "$txid_four"
tx_dir_four="$(fip_tx_dir "$tx_root_four" "$txid_four")"
# Corte exacto: decision durable escrita, phase todavía verified.
fip_tx_atomic_text "$tx_dir_four/decision" 0600 commit
[[ "$(fip_tx_phase "$tx_root_four" "$txid_four")" == verified ]]
fip_tx_decide_commit "$tx_root_four" "$txid_four"
[[ "$(fip_tx_phase "$tx_root_four" "$txid_four")" == commit-decided ]]
if fip_tx_begin_rollback "$tx_root_four" "$txid_four"; then
  echo 'se permitio rollback despues de commit-decided' >&2
  exit 1
fi
fip_tx_mark_committed "$tx_root_four" "$txid_four" "$data_four" "$template_four"
assert_file_text "$template_four" '<Container>committed</Container>'
fip_tx_cleanup "$tx_root_four" "$txid_four"
if docker inspect "$old_four_cid" >/dev/null 2>&1; then
  echo 'el contenedor anterior sobrevivio al commit' >&2
  exit 1
fi
[[ "$(docker inspect --format '{{.Id}}' Keepalived)" == "$candidate_four_cid" ]]
[[ ! -e "$tx_root_four/active" && ! -e "$data_four/.deploy-freeze" ]]
remove_container_fixture candidate-four

if grep -Eq -- '--signal=(KILL|SIGKILL)|docker (kill|stop).*KILL' \
    "$repo_root/deploy-transaction-lib.sh"; then
  echo 'la libreria contiene una via SIGKILL' >&2
  exit 1
fi
recursive_delete='rm -r''f'
if grep -Fq "$recursive_delete" "$repo_root/deploy-transaction-lib.sh" \
    || grep -Fq "$recursive_delete" "$0"; then
  echo 'se encontro un borrado recursivo no permitido' >&2
  exit 1
fi

printf '%s\n' 'deploy transaction tests: OK'
