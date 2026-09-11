#!/usr/bin/env bash
# Copia este fichero a manifiesto.local.sh o a una ruta fuera del repositorio.
# Sustituye los valores de ejemplo por los de TU red y tus servidores.
# No guardes aquí claves ni contraseñas. Usa FIP_VRRP_AUTH_FILE,
# FIP_SESSION_SECRET_FILE, FIP_CLUSTER_TOKEN_FILE y FIP_SECRETS_DIR desde el
# entorno de despliegue.
# shellcheck disable=SC2034  # Este fichero se carga con source desde el despliegue.

DHCP_DESDE=200
# Contrato de red de la versión 1.0.2: debe ser exactamente 24.
VIP_PREFIJO=24

# nombre:ip del nodo:interfaz:prioridad base:fichero de clave SSH
# 192.0.2.0/24 está reservado para ejemplos documentales (RFC 5737).
NODOS=(
  "node-a:192.0.2.10:eth0:150:ssh_key_node_a"
  "node-b:192.0.2.11:eth0:100:ssh_key_node_b"
  "node-c:192.0.2.12:eth0:50:ssh_key_node_c"
)

# nombre:IP flotante:VRID:puerto de salud:ruta de salud:servidor por defecto
DIRECCIONES=(
  "service-a:192.0.2.100:51:8080:/health:node-a"
)
PREEMPT_DELAY=45

# Opcional: "nombre=host:puerto,nombre=host:puerto" para mirrors privados.
# Si no se define, todos descargan la release pública versionada de GHCR.
# REGISTROS_POR_NODO="node-a=registry.example:5000,node-b=registry.example:5000"
# El despliegue real exige FIP_IMAGE_DIGEST=sha256:<64 hex> obtenido de la
# release verificada; nunca decide confianza a partir de una etiqueta mutable.
