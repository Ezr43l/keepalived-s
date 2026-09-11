#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
test_root="$(mktemp -d)"
cleanup_test_root() {
  if [[ -z "${KEEP_TEST_TMP:-}" ]]; then
    find "$test_root" -depth -delete
  else
    printf 'test tmp: %s\n' "$test_root"
  fi
}
trap cleanup_test_root EXIT
mkdir -p "$test_root/bin" "$test_root/secrets"
chmod 0700 "$test_root/secrets"

manifest="$test_root/manifest.sh"
cat > "$manifest" <<'MANIFEST'
DHCP_DESDE=200
VIP_PREFIJO=24
NODOS=(
  "node-a:192.0.2.10:eth0:150:ssh-a"
  "node-b:192.0.2.11:eth0:100:ssh-b"
)
DIRECCIONES=("service-a:192.0.2.100:51:8080:/health:node-a")
MANIFEST

printf '%s\n' 'not-a-real-key' > "$test_root/secrets/ssh-a"
printf '%s\n' 'not-a-real-key' > "$test_root/secrets/ssh-b"
printf '%s\n' 'VrrpKey1' > "$test_root/secrets/keepalived-vrrp.txt"
printf '%s\n' 'ssssssssssssssssssssssssssssssssssssssss' \
  > "$test_root/secrets/keepalived-session-secret.txt"
printf '%s\n' 'cccccccccccccccccccccccccccccccccccccccc' \
  > "$test_root/secrets/keepalived-cluster-token.txt"
chmod 0600 "$test_root/secrets"/*

cat > "$test_root/bin/ssh" <<'MOCK_SSH'
#!/usr/bin/env bash
set -euo pipefail
for opcion in BatchMode=yes IdentitiesOnly=yes StrictHostKeyChecking=yes \
    UserKnownHostsFile= ConnectionAttempts=1 ServerAliveInterval=5 \
    ServerAliveCountMax=2; do
  [[ "$*" == *"$opcion"* ]] || {
    echo "falta opción SSH estricta: $opcion" >&2
    exit 91
  }
done
[[ "$*" != *accept-new* ]] || exit 91
host=desconocido
[[ "$*" == *root@192.0.2.10* ]] && host=node-a
[[ "$*" == *root@192.0.2.11* ]] && host=node-b
if [[ "$*" == *'for utilidad in bash docker'* ]]; then
  epoch="$(date +%s)"
  if [[ "$host" == node-b && -n "${MOCK_CLOCK_SKEW:-}" ]]; then
    epoch=$((epoch + 100))
  fi
  printf 'capability-ok;%s\n' "$epoch"
  exit 0
fi
if [[ -n "${MOCK_RECOVERY_COMMIT:-}" \
    && "$*" == *'io.ezr43l.deploy-image-digest'* ]]; then
  printf 'recovery-evidence %s\n' "$host" >> "$MOCK_SSH_LOG"
  printf '%064d|sha256:%064d|sha256:%064d\n' 7 8 9
  exit 0
fi
if [[ -n "${MOCK_RECOVERY_ROLLBACK:-}" && "$*" == *'fip-rb-'* ]]; then
  printf 'rollback-evidence %s\n' "$host" >> "$MOCK_SSH_LOG"
  exit 0
fi
if [[ "$*" == *'bash -s'* ]]; then
  payload="$(cat)"
  if printf '%s\n' "$payload" | grep -Fq 'fip_tx_discover "$@"'; then
    if [[ -n "${MOCK_RECOVERY_COMMIT:-}" && "$host" == node-a ]]; then
      printf '%s\n' \
        'txid=99999999999999999999999999999999;phase=commit-decided;decision=commit'
    elif [[ -n "${MOCK_RECOVERY_ROLLBACK:-}" && "$host" == node-a ]]; then
      printf '%s\n' \
        'txid=88888888888888888888888888888888;phase=rolled-back;decision=none'
    else
      printf '%s\n' none
    fi
    exit 0
  fi
  if [[ -n "${MOCK_RECOVERY_COMMIT:-}" ]]; then
    case "$(printf '%s\n' "$payload" | tail -n 1)" in
      'fip_tx_install_template "$@"') accion=install ;;
      'fip_tx_mark_committed "$@"') accion=committed ;;
      'fip_tx_cleanup "$@"') accion=cleanup ;;
      *) accion="" ;;
    esac
    if [[ -n "$accion" ]]; then
      printf 'recovery-%s %s\n' "$accion" "$host" >> "$MOCK_SSH_LOG"
      exit 0
    fi
  fi
  if [[ -n "${MOCK_RECOVERY_ROLLBACK:-}" ]]; then
    case "$(printf '%s\n' "$payload" | tail -n 1)" in
      'fip_tx_get_mode "$@"') exit 1 ;;
      'fip_tx_cleanup "$@"')
        printf 'rollback-cleanup %s\n' "$host" >> "$MOCK_SSH_LOG"
        exit 0
        ;;
    esac
  fi
  printf 'unexpected-tx %s\n' "$host" >> "$MOCK_SSH_LOG"
  exit 90
fi
if [[ "$*" == *auditar_identidad_remota* ]]; then
  printf 'identity %s\n' "$host" >> "$MOCK_SSH_LOG"
  if [[ "${MOCK_IDENTITY_WRITER:-}" == "" ]]; then
    printf '%s\n' absent
  elif [[ "$*" == *root@192.0.2.10* ]]; then
    printf 'node=node-a;writer=%s;protocol=%s\n' \
      "$MOCK_IDENTITY_WRITER" "${MOCK_PROTOCOL:-v2}"
  else
    printf 'node=node-b;writer=%s;protocol=%s\n' \
      "$MOCK_IDENTITY_WRITER" "${MOCK_PROTOCOL:-v2}"
  fi
  exit 0
fi
if [[ "$*" == *auditar_control_remoto* ]]; then
  printf 'control %s\n' "$host" >> "$MOCK_SSH_LOG"
  if [[ -n "${MOCK_CONTROL_FAIL:-}" ]]; then
    echo 'almacenamiento de control simulado no válido' >&2
    exit 1
  fi
  printf '%s\n' marker=absent
  exit 0
fi
if [[ "$*" == *auditar_artefacto_actual_remoto* ]]; then
  printf 'artifact %s\n' "$host" >> "$MOCK_SSH_LOG"
  if [[ "${MOCK_IDENTITY_WRITER:-}" == "" ]]; then
    printf '%s\n' artifact=absent
  elif [[ "${MOCK_PROTOCOL:-v2}" == legacy ]]; then
    printf '%s\n' artifact=legacy
  else
    printf 'artifact=v2;revision=%040d;digest=registry.example/floating-ip@sha256:%064d;image=sha256:%064d\n' \
      1 2 3
  fi
  exit 0
fi
pool_state='{"actualizado":"2026-01-02T03:04:05+00:00","dhcp_desde":200,"direcciones":[],"mantenimiento":[],"reclamaciones":{},"version":1}'
security_state='{"api_keys":[],"revision":{"counter":0,"node":"","timestamp":0},"schema":1,"users":[]}'
if [[ "$host" == node-b && -n "${MOCK_STATE_DIVERGENT:-}" ]]; then
  pool_state='{"actualizado":"2026-01-02T03:04:05+00:00","dhcp_desde":201,"direcciones":[],"mantenimiento":[],"reclamaciones":{},"version":1}'
fi
if [[ "$*" == *observar_estado_remoto* ]]; then
  if [[ "$*" == *"'pool.json'"* ]]; then
    contenido="$pool_state"
  else
    contenido="$security_state"
  fi
  huella="$(printf '%s\n' "$contenido" | sha256sum | cut -d' ' -f1)"
  bytes="$(printf '%s\n' "$contenido" | wc -c | tr -d ' ')"
  printf 'present;%s;%s\n' "$huella" "$bytes"
  exit 0
fi
if [[ "$*" == *descargar_estado_remoto* ]]; then
  if [[ "$*" == *"'pool.json'"* ]]; then
    printf '%s\n' "$pool_state"
  else
    printf '%s\n' "$security_state"
  fi
  exit 0
fi
if [[ "$*" == *"Target=.FIP_PUERTO"* ]]; then
  printf 'port %s\n' "$host" >> "$MOCK_SSH_LOG"
  printf '%s\n' "${MOCK_REMOTE_PORT:-6060}"
  exit 0
fi
if [[ "$*" == *"ip link show dev"* ]]; then
  printf 'topology %s\n' "$host" >> "$MOCK_SSH_LOG"
  exit "${MOCK_TOPOLOGY_EXIT:-0}"
fi
if [[ "$*" == *"docker pull -q"* ]]; then
  printf 'image %s\n' "$host" >> "$MOCK_SSH_LOG"
  printf 'sha256:%064d|%040d|%s|v2\n' 3 1 \
    "$(tr -d ' \r\n' < "$MOCK_REPO_ROOT/VERSION")"
  exit 0
fi
if [[ "$*" == *"preflight_remoto.py"* ]]; then
  printf 'validator %s\n' "$host" >> "$MOCK_SSH_LOG"
  cat >/dev/null
  if [[ -n "${MOCK_STATE_DIVERGENT:-}" ]]; then
    printf '%s\n' '{"ok":false,"error":{"code":"PREFLIGHT_STATE_DIVERGENT"}}'
    exit 42
  fi
  printf '%s\n' '{"ok":true}'
  exit 0
fi
[[ "$*" == *auditar_secretos_remotos* ]] || {
  printf 'unexpected %s\n' "$host" >> "$MOCK_SSH_LOG"
  echo "se alcanzó una fase mutante tras fallar el preflight" >&2
  exit 90
}
printf 'secrets %s\n' "$host" >> "$MOCK_SSH_LOG"
if [[ -n "${MOCK_ALL_SECRETS_MISSING:-}" \
    || ( "$host" == node-b && -n "${MOCK_NODE_B_SECRETS_MISSING:-}" ) ]]; then
  printf '%s\n' vrrp=missing session=missing cluster=missing
elif [[ "$*" == *root@192.0.2.10* || -z "${MOCK_SECRET_MISMATCH:-}" ]]; then
  printf 'vrrp=%s\nsession=%s\ncluster=%s\n' \
    "$EXPECTED_VRRP" "$EXPECTED_SESSION" "$EXPECTED_CLUSTER"
else
  printf 'vrrp=%064d\nsession=%s\ncluster=%s\n' \
    0 "$EXPECTED_SESSION" "$EXPECTED_CLUSTER"
fi
MOCK_SSH
chmod 0755 "$test_root/bin/ssh"

cat > "$test_root/bin/curl" <<'MOCK_CURL'
#!/usr/bin/env bash
exit 90
MOCK_CURL
chmod 0755 "$test_root/bin/curl"

cat > "$test_root/bin/date" <<'MOCK_DATE'
#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${MOCK_CLOCK_SEQUENCE:-}" ]]; then
  exec /bin/date "$@"
fi
[[ "${1:-}" == +%s ]]
contador=0
if [[ -s "$MOCK_DATE_STATE" ]]; then
  IFS= read -r contador < "$MOCK_DATE_STATE"
fi
if [[ -n "${MOCK_CLOCK_WIDE_RTT:-}" ]]; then
  case "$contador" in
    0) epoch=2000000000 ;;
    1) epoch=2000000005 ;;
    *) epoch=2000000020 ;;
  esac
else
  case "$contador" in
    0) epoch=2000000000 ;;
    1) epoch=2000000002 ;;
    2) epoch=2000000004 ;;
    3) epoch=2000000040 ;;
    4) epoch=2000000042 ;;
    5) epoch=2000000044 ;;
    *) epoch=2000000044 ;;
  esac
fi
printf '%s\n' "$((contador + 1))" > "$MOCK_DATE_STATE"
printf '%s\n' "$epoch"
MOCK_DATE
chmod 0755 "$test_root/bin/date"

cat > "$test_root/bin/ssh-keygen" <<'MOCK_SSH_KEYGEN'
#!/usr/bin/env bash
exit 0
MOCK_SSH_KEYGEN
chmod 0755 "$test_root/bin/ssh-keygen"

known_hosts="$test_root/known_hosts"
printf '%s\n' 'mock known-hosts content' > "$known_hosts"
chmod 0600 "$known_hosts"

export MOCK_SSH_LOG="$test_root/ssh.log"
export MOCK_REPO_ROOT="$repo_root"
export MOCK_DATE_STATE="$test_root/date-state"
export FIP_KNOWN_HOSTS_FILE="$known_hosts"
export MOCK_SECRET_MISMATCH=1
EXPECTED_VRRP="$(printf '%s\n' 'VrrpKey1' | sha256sum | cut -d' ' -f1)"
EXPECTED_SESSION="$(printf '%s\n' \
  'ssssssssssssssssssssssssssssssssssssssss' | sha256sum | cut -d' ' -f1)"
EXPECTED_CLUSTER="$(printf '%s\n' \
  'cccccccccccccccccccccccccccccccccccccccc' | sha256sum | cut -d' ' -f1)"
export EXPECTED_VRRP EXPECTED_SESSION EXPECTED_CLUSTER

if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-digest" 2>&1; then
  echo "El despliegue aceptó decidir confianza desde una etiqueta mutable." >&2
  exit 1
fi
grep -Fq 'Falta FIP_IMAGE_DIGEST' "$test_root/out-digest"
[[ ! -e "$MOCK_SSH_LOG" || ! -s "$MOCK_SSH_LOG" ]]
FIP_IMAGE_DIGEST="sha256:$(printf '%064d' 2)"
export FIP_IMAGE_DIGEST
export MOCK_CLOCK_SEQUENCE=1
: > "$MOCK_DATE_STATE"

if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out" 2>&1; then
  echo "El despliegue aceptó una divergencia remota de secretos." >&2
  exit 1
fi
unset MOCK_CLOCK_SEQUENCE

grep -Fq "el secreto remoto 'vrrp' no coincide" "$test_root/out"
grep -Fq 'identity node-a' "$MOCK_SSH_LOG"
grep -Fq 'control node-a' "$MOCK_SSH_LOG"
grep -Fq 'artifact node-a' "$MOCK_SSH_LOG"
grep -Fq 'secrets node-a' "$MOCK_SSH_LOG"
grep -Fq 'identity node-b' "$MOCK_SSH_LOG"
grep -Fq 'control node-b' "$MOCK_SSH_LOG"
grep -Fq 'artifact node-b' "$MOCK_SSH_LOG"
grep -Fq 'secrets node-b' "$MOCK_SSH_LOG"
test "$(wc -l < "$MOCK_SSH_LOG")" -eq 8
if grep -Fq 'unexpected' "$MOCK_SSH_LOG"; then
  echo "El preflight divergente alcanzó una operación mutante." >&2
  exit 1
fi

# El tiempo secuencial entre dos SSH no es deriva: cada muestra individual
# conserva un RTT acotado y su epoch queda en su propia ventana before/after.
if grep -Fq 'deriva de reloj' "$test_root/out"; then
  echo "El RTT secuencial se confundió con deriva de reloj." >&2
  exit 1
fi

# Un offset real superior a la ventana sí aborta antes de las auditorías.
: > "$MOCK_SSH_LOG"
export MOCK_CLOCK_SKEW=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-clock" 2>&1; then
  echo "El despliegue aceptó una deriva de reloj superior a la ventana HMAC." >&2
  exit 1
fi
grep -Fq 'deriva de reloj del clúster supera' "$test_root/out-clock"
test ! -s "$MOCK_SSH_LOG"
unset MOCK_CLOCK_SKEW

# Una muestra individual demasiado ancha no puede acreditar la ventana HMAC,
# aunque el epoch remoto pudiera caer dentro de ese intervalo.
: > "$MOCK_SSH_LOG"
: > "$MOCK_DATE_STATE"
export MOCK_CLOCK_SEQUENCE=1 MOCK_CLOCK_WIDE_RTT=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-clock-rtt" 2>&1; then
  echo "El despliegue aceptó una muestra de reloj con RTT inseguro." >&2
  exit 1
fi
grep -Fq 'RTT es demasiado amplio' "$test_root/out-clock-rtt"
test ! -s "$MOCK_SSH_LOG"
unset MOCK_CLOCK_SEQUENCE MOCK_CLOCK_WIDE_RTT

# Commit-wins se recupera desde la evidencia del candidato antiguo, no desde el
# FIP_IMAGE_DIGEST (distinto) solicitado por esta nueva invocación.
: > "$MOCK_SSH_LOG"
export MOCK_RECOVERY_COMMIT=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-recovery-digest" 2>&1; then
  echo "La prueba de recovery esperaba detenerse después en secretos divergentes." >&2
  exit 1
fi
grep -Fq "el secreto remoto 'vrrp' no coincide" "$test_root/out-recovery-digest"
grep -Fq 'recovery-evidence node-a' "$MOCK_SSH_LOG"
grep -Fq 'recovery-evidence node-b' "$MOCK_SSH_LOG"
grep -Fq 'recovery-install node-a' "$MOCK_SSH_LOG"
grep -Fq 'recovery-committed node-a' "$MOCK_SSH_LOG"
grep -Fq 'recovery-cleanup node-a' "$MOCK_SSH_LOG"
if grep -Fq 'no acredita el candidato' "$test_root/out-recovery-digest"; then
  echo "Recovery dependió erróneamente del digest de la invocación nueva." >&2
  exit 1
fi
unset MOCK_RECOVERY_COMMIT

# Un rollback ya limpiado en un peer y aún durable en el escritor sólo termina
# los journals restantes; no vuelve a snapshot ni cae en abort legacy.
: > "$MOCK_SSH_LOG"
export MOCK_RECOVERY_ROLLBACK=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-recovery-rollback" 2>&1; then
  echo "La prueba de rollback parcial esperaba detenerse después en secretos." >&2
  exit 1
fi
grep -Fq "el secreto remoto 'vrrp' no coincide" "$test_root/out-recovery-rollback"
grep -Fq 'rollback-evidence node-b' "$MOCK_SSH_LOG"
grep -Fq 'rollback-cleanup node-a' "$MOCK_SSH_LOG"
if grep -Fq 'unexpected-tx' "$MOCK_SSH_LOG"; then
  echo "Recovery de rollback parcial eligió una acción no reanudable." >&2
  exit 1
fi
unset MOCK_RECOVERY_ROLLBACK

: > "$MOCK_SSH_LOG"
unset MOCK_SECRET_MISMATCH
export MOCK_ALL_SECRETS_MISSING=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-all-missing" 2>&1; then
  echo "El despliegue aceptó sustituir todos los secretos remotos ausentes." >&2
  exit 1
fi
grep -Fq "ninguna copia remota acreditada del secreto 'vrrp'" \
  "$test_root/out-all-missing"
if grep -Fq 'unexpected' "$MOCK_SSH_LOG"; then
  echo "La puerta all-missing alcanzó una operación mutante." >&2
  exit 1
fi

: > "$MOCK_SSH_LOG"
unset MOCK_ALL_SECRETS_MISSING
export MOCK_NODE_B_SECRETS_MISSING=1
export MOCK_STATE_DIVERGENT=1
export MOCK_IDENTITY_WRITER=node-a
export MOCK_PROTOCOL=v2
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" \
      >"$test_root/out-replacement-secret" 2>&1; then
  echo "La prueba de reemplazo esperaba detenerse en el estado causal divergente." >&2
  exit 1
fi
grep -Fq 'PREFLIGHT_STATE_DIVERGENT' "$test_root/out-replacement-secret"
grep -Fq 'validator node-a' "$MOCK_SSH_LOG"
if grep -Fq 'ninguna copia remota acreditada' "$test_root/out-replacement-secret"; then
  echo "Se rechazó reparar un nodo sin secretos pese a existir una copia acreditada." >&2
  exit 1
fi
unset MOCK_NODE_B_SECRETS_MISSING MOCK_STATE_DIVERGENT

: > "$MOCK_SSH_LOG"
export MOCK_IDENTITY_WRITER=node-b
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-identity" 2>&1; then
  echo "El despliegue aceptó cambiar la identidad del escritor." >&2
  exit 1
fi
grep -Fq "cambiaría el escritor de 'node-b' a 'node-a'" "$test_root/out-identity"
test "$(wc -l < "$MOCK_SSH_LOG")" -eq 1
grep -Fq 'identity node-a' "$MOCK_SSH_LOG"
if grep -Eq 'secrets|unexpected' "$MOCK_SSH_LOG"; then
  echo "El preflight de identidad divergente alcanzó una fase posterior." >&2
  exit 1
fi

: > "$MOCK_SSH_LOG"
export MOCK_IDENTITY_WRITER=node-a
export MOCK_PROTOCOL=v2
export MOCK_CONTROL_FAIL=1
unset MOCK_SECRET_MISMATCH
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" >"$test_root/out-control" 2>&1; then
  echo "El despliegue aceptó un almacenamiento de control no auditable." >&2
  exit 1
fi
grep -Fq 'almacenamiento de control existente no supera la auditoría' \
  "$test_root/out-control"
test "$(wc -l < "$MOCK_SSH_LOG")" -eq 2
grep -Fq 'identity node-a' "$MOCK_SSH_LOG"
grep -Fq 'control node-a' "$MOCK_SSH_LOG"
if grep -Eq 'secrets|unexpected' "$MOCK_SSH_LOG"; then
  echo "La puerta de almacenamiento alcanzó una fase posterior." >&2
  exit 1
fi

: > "$MOCK_SSH_LOG"
export MOCK_IDENTITY_WRITER=node-a
export MOCK_PROTOCOL=legacy
unset MOCK_CONTROL_FAIL
unset MOCK_SECRET_MISMATCH
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" node-a \
      >"$test_root/out-cohort" 2>&1; then
  echo "El despliegue aceptó una selección real parcial." >&2
  exit 1
fi
grep -Fq 'exige seleccionar el clúster completo (N/N)' "$test_root/out-cohort"
test ! -s "$MOCK_SSH_LOG"
if grep -Fq 'unexpected' "$MOCK_SSH_LOG"; then
  echo "La puerta de cohorte alcanzó una fase mutante." >&2
  exit 1
fi

: > "$MOCK_SSH_LOG"
export MOCK_PROTOCOL=v2
export MOCK_REMOTE_PORT=6060
export MOCK_STATE_DIVERGENT=1
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" \
      >"$test_root/out-state" 2>&1; then
  echo "El despliegue aceptó estados legacy divergentes antes de parar." >&2
  exit 1
fi
grep -Fq 'PREFLIGHT_STATE_DIVERGENT' "$test_root/out-state"
if grep -Fq 'unexpected' "$MOCK_SSH_LOG"; then
  echo "El preflight causal divergente alcanzó una fase mutante." >&2
  exit 1
fi

: > "$MOCK_SSH_LOG"
unset MOCK_STATE_DIVERGENT
export MOCK_REMOTE_PORT=70000
if PATH="$test_root/bin:$PATH" \
    FIP_MANIFIESTO="$manifest" FIP_SECRETS_DIR="$test_root/secrets" \
    bash "$repo_root/deploy-floating-ip.sh" \
      >"$test_root/out-port" 2>&1; then
  echo "El despliegue aceptó un puerto persistido fuera de rango." >&2
  exit 1
fi
grep -Fq 'la plantilla conserva un puerto no válido' "$test_root/out-port"
grep -Fq 'port node-a' "$MOCK_SSH_LOG"
if grep -Eq 'topology|unexpected' "$MOCK_SSH_LOG"; then
  echo "La puerta de puerto inválido alcanzó una fase posterior." >&2
  exit 1
fi

printf '%s\n' 'deploy secret preflight tests: OK'
