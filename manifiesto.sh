#!/usr/bin/env bash
# Cargador de configuración de una instalación de floating-ip.
# La topología, las direcciones y las credenciales pertenecen a cada instalación,
# no al producto compartido. El despliegue busca FIP_MANIFIESTO o
# manifiesto.local.sh junto a este repositorio.

_BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
_CONFIG="${FIP_MANIFIESTO:-${MANIFIESTO:-$_BASE_DIR/manifiesto.local.sh}}"
if [[ ! -r "$_CONFIG" ]]; then
  echo "❌ No existe el manifiesto de esta instalación: $_CONFIG" >&2
  echo "   Copia manifiesto.example.sh a un fichero local y define FIP_MANIFIESTO=/ruta/al/fichero." >&2
  # shellcheck disable=SC2317  # Debe funcionar tanto con source como ejecutado.
  return 2 2>/dev/null || exit 2
fi
# shellcheck disable=SC1090
source "$_CONFIG"
