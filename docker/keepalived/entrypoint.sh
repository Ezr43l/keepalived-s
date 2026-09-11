#!/bin/sh
# Arranca las dos piezas del contenedor: el panel y keepalived.
#
# Van juntas para que Docker supervise una única unidad coherente. Las
# actualizaciones se hacen nodo a nodo después de drenar sus direcciones.
#
# ORDEN: primero el panel. Keepalived sólo nace después de que el panel haya
# reconciliado el pool con quorum y publicado un marcador atómico. Un nodo que
# vuelve aislado no puede anunciar direcciones desde un registro obsoleto.
set -eu

# La primera ejecucion sirve el asistente. En instalaciones anteriores migra
# las FIP_* y sus secretos al volumen antes de continuar. El fichero vive en
# /run, se genera con quoting de shell y desaparece con el contenedor.
ENTORNO=/run/floating-ip/app-environment
mkdir -p "$(dirname "$ENTORNO")"
umask 077
python3 /opt/panel/bootstrap.py > "$ENTORNO"
# shellcheck disable=SC1090
. "$ENTORNO"
rm -f "$ENTORNO"

DRENAR="${FIP_DRENAR:-/run/floating-ip/drenar}"
LISTO="${FIP_READY_MARKER:-/run/floating-ip/pool-ready}"
mkdir -p "$DRENAR"
mkdir -p "$(dirname "$LISTO")"
rm -f "$LISTO"

python3 /opt/panel/servidor.py &
PANEL=$!
KA=""

# Invocada indirectamente por trap.
# shellcheck disable=SC2329
terminar() {
  [ -z "$KA" ] || kill -TERM "$KA" 2>/dev/null || true
  kill -TERM "$PANEL" 2>/dev/null || true
  exit 0
}

# Invocada indirectamente por trap.
# shellcheck disable=SC2329
recargar() {
  [ -z "$KA" ] || kill -HUP "$KA" 2>/dev/null || true
}

trap recargar HUP
trap terminar TERM INT

while [ ! -f "$LISTO" ]; do
  if ! kill -0 "$PANEL" 2>/dev/null; then
    echo "el panel terminó antes de reconciliar el pool; keepalived no se inicia" >&2
    wait "$PANEL" 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Cierra la carrera entre observar el marcador y lanzar keepalived.
if ! kill -0 "$PANEL" 2>/dev/null; then
  echo "el panel terminó al completar el arranque; keepalived no se inicia" >&2
  wait "$PANEL" 2>/dev/null || true
  exit 1
fi

keepalived --dont-fork --log-console --log-detail \
  -f "${FIP_CONF:-/etc/keepalived/keepalived.conf}" &
KA=$!

# SIGHUP se reenvía a keepalived para recargar su configuración en caliente.
# Si cualquiera de los dos se muere, se sale para que Docker recree el
# contenedor entero. Un contenedor a medias —keepalived vivo y panel muerto, o
# al reves— es peor que uno reiniciandose: parece sano y no lo esta.
while kill -0 "$PANEL" 2>/dev/null && kill -0 "$KA" 2>/dev/null; do
  sleep 5
done

kill -0 "$KA" 2>/dev/null || echo "keepalived ha terminado; se sale para que Docker recree" >&2
kill -0 "$PANEL" 2>/dev/null || echo "el panel ha terminado; se sale para que Docker recree" >&2
kill -TERM "$KA" "$PANEL" 2>/dev/null || true
exit 1
