#!/bin/sh
# Prueba HTTP aislada del acceso. No necesita keepalived ni modifica un pool real.
set -eu

URL="${1:?URL del panel temporal}"
CLAVE="${2:?contraseña del administrador inicial}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
COOKIE="$TMP/cookies"

codigo() { # <esperado> <metodo> <ruta> <salida> [curl args...]
  esperado="$1"; metodo="$2"; ruta="$3"; salida="$4"; shift 4
  real="$(curl -sS -o "$salida" -w '%{http_code}' -X "$metodo" "$@" "$URL$ruta")"
  [ "$real" = "$esperado" ] || {
    echo "Fallo $metodo $ruta: HTTP $real, esperado $esperado" >&2
    exit 1
  }
}

json() { # <fichero> <campo>
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

crear_json() { # pares clave valor
  python3 -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2],sys.argv[2::2]))))' "$@"
}

codigo 200 GET /api/health "$TMP/health"
codigo 200 GET /api/auth/status "$TMP/status"
[ "$(json "$TMP/status" registration_required)" = "True" ]
codigo 401 GET /api/direcciones "$TMP/anonimo"

NO_COINCIDE="$(crear_json username admin display_name Administrador password "$CLAVE" password_confirmation "Distinta-Prueba-2026")"
codigo 422 POST /api/auth/session "$TMP/mismatch" \
  -H 'Content-Type: application/json' --data "$NO_COINCIDE"
[ "$(json "$TMP/mismatch" code)" = "PASSWORD_CONFIRMATION_MISMATCH" ]

LOGIN="$(crear_json username admin display_name Administrador password "$CLAVE" password_confirmation "$CLAVE" otp '')"
codigo 200 POST /api/auth/session "$TMP/login" -c "$COOKIE" \
  -H 'Content-Type: application/json' --data "$LOGIN"
[ "$(json "$TMP/login" password_change_required)" = "False" ]
[ "$(json "$TMP/login" login_method)" = "registration" ]
CSRF="$(json "$TMP/login" csrf_token)"
codigo 200 GET /api/auth/status "$TMP/status-registered"
[ "$(json "$TMP/status-registered" registration_required)" = "False" ]
OTRA="$(crear_json username otro password "Otra-Clave-Segura-2026" password_confirmation "Otra-Clave-Segura-2026")"
codigo 401 POST /api/auth/session "$TMP/second-registration" \
  -H 'Content-Type: application/json' --data "$OTRA"
codigo 200 GET /api/direcciones "$TMP/direcciones" -b "$COOKIE"

CLAVE_JSON="$(python3 -c 'import json,sys; print(json.dumps({"name":"smoke-reader","scopes":["status:read"],"current_password":sys.argv[1],"otp":""}))' "$CLAVE")"
codigo 201 POST /api/api-keys "$TMP/key" -b "$COOKIE" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" --data "$CLAVE_JSON"
TOKEN="$(json "$TMP/key" token)"
KEY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["api_key"]["id"])' "$TMP/key")"
codigo 200 GET /api/direcciones "$TMP/direcciones-api" -H "Authorization: Bearer $TOKEN"
codigo 403 POST /api/claims "$TMP/scope" -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: smoke:test:0001' -H 'Content-Type: application/json' \
  --data '{"servicio":"smoke","puertos":[8080],"chequeo":{"puerto":8080,"ruta":"/health"}}'

REVOCAR="$(crear_json current_password "$CLAVE" otp '')"
codigo 200 DELETE "/api/api-keys/$KEY_ID" "$TMP/revoke" -b "$COOKIE" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" --data "$REVOCAR"
codigo 401 GET /api/direcciones "$TMP/revoked" -H "Authorization: Bearer $TOKEN"

SETUP="$(crear_json current_password "$CLAVE")"
codigo 200 POST /api/profile/2fa/setup "$TMP/setup" -b "$COOKIE" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" --data "$SETUP"
SECRETO="$(json "$TMP/setup" secret)"
OTP="$(python3 -c 'import base64,hashlib,hmac,struct,sys,time; s=sys.argv[1]; s += "="*((-len(s))%8); k=base64.b32decode(s); c=int(time.time())//30; d=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=d[-1]&15; print(str((struct.unpack(">I",d[o:o+4])[0]&0x7fffffff)%1000000).zfill(6))' "$SECRETO")"
ACTIVAR="$(crear_json code "$OTP")"
codigo 200 POST /api/profile/2fa/enable "$TMP/enable" -b "$COOKIE" -c "$COOKIE" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" --data "$ACTIVAR"
[ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["recovery_codes"]))' "$TMP/enable")" = "10" ]

SIN_OTP="$(crear_json username admin password "$CLAVE" otp '')"
codigo 401 POST /api/auth/session "$TMP/no-otp" -H 'Content-Type: application/json' --data "$SIN_OTP"
[ "$(json "$TMP/no-otp" code)" = "TWO_FACTOR_REQUIRED" ]
OTP="$(python3 -c 'import base64,hashlib,hmac,struct,sys,time; s=sys.argv[1]; s += "="*((-len(s))%8); k=base64.b32decode(s); c=int(time.time())//30; d=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=d[-1]&15; print(str((struct.unpack(">I",d[o:o+4])[0]&0x7fffffff)%1000000).zfill(6))' "$SECRETO")"
CON_OTP="$(crear_json username admin password "$CLAVE" otp "$OTP")"
codigo 200 POST /api/auth/session "$TMP/with-otp" -H 'Content-Type: application/json' --data "$CON_OTP"

echo "AUTH_SMOKE_OK"
