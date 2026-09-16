<p align="center">
  <img src="assets/github-banner.svg" alt="Keepalived — direcciones flotantes y alta disponibilidad" width="100%">
</p>

<p align="center">
  <img alt="Un contenedor" src="https://img.shields.io/badge/despliegue-1%20contenedor-55df9a">
  <img alt="VRRP" src="https://img.shields.io/badge/red-VRRP-12cddd">
  <a href="LICENSE"><img alt="Licencia Apache 2.0" src="https://img.shields.io/badge/licencia-Apache--2.0-7d91a3"></a>
</p>

# Keepalived

Keepalived administra direcciones IPv4 flotantes para servicios que pueden cambiar de
servidor. Comprueba la salud real de cada servicio y mueve su dirección al nodo disponible
que corresponda.

El panel, la API y el proceso de red se ejecutan en un único contenedor para Linux
`amd64` y `arm64`.

## Qué ofrece

- Direcciones flotantes mediante VRRP.
- Comprobaciones de salud por servicio y nodo.
- Distribución determinista de direcciones.
- Modo de mantenimiento y drenaje de nodos.
- Detección de direcciones duplicadas y servicios sin respuesta.
- Pool de direcciones para aplicaciones.
- Usuarios, roles y segundo factor TOTP.
- Credenciales API independientes y revocables.
- Configuración y secretos persistentes.

## Requisitos

- Docker Engine en un servidor Linux.
- Red local donde los nodos puedan comunicarse entre sí.
- Direcciones libres fuera del rango DHCP.
- Permisos de red `NET_ADMIN`, `NET_BROADCAST` y `NET_RAW`.
- Un volumen persistente por nodo.

Keepalived necesita utilizar la red real del servidor. No funciona como servicio de alta
disponibilidad si la red bloquea VRRP o la comunicación entre nodos.

## Instalación con Docker

```bash
sudo mkdir -p /srv/keepalived

sudo docker run -d \
  --name keepalived \
  --restart unless-stopped \
  --init \
  --network host \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_BROADCAST \
  --cap-add NET_RAW \
  --cap-add SETGID \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --tmpfs /run:rw,nosuid,noexec,size=32m \
  --tmpfs /tmp:rw,nosuid,noexec,size=32m \
  -v /srv/keepalived:/datos \
  ghcr.io/ezr43l/keepalived-s:stable
```

Abre `http://SERVIDOR:6060`. El asistente crea la cuenta inicial y solicita la
identidad del nodo, la interfaz de red y los miembros del grupo.

También están disponibles [Docker Compose](docker-compose.yml), la
[guía de instalación](docs/instalacion.md) y una
[plantilla para Unraid](unraid/my-Keepalived.xml).

## Configuración del grupo

Configura primero un nodo y utiliza su código de incorporación para añadir los demás.
Todos los miembros deben declarar los nodos en el mismo orden y poder comunicarse por sus
direcciones de gestión.

Después crea el pool de direcciones flotantes y asocia cada servicio con su puerto y su
comprobación de salud. Una máquina encendida no se considera apta si la aplicación que
debe atender la dirección está caída.

## API para aplicaciones

Cada integración debe tener su propia credencial. Una aplicación puede solicitar una
dirección de manera repetible:

```http
POST /api/claims
Authorization: Bearer fip_ID_SECRETO
Idempotency-Key: provision:identificador-unico
Content-Type: application/json
```

```json
{
  "servicio": "service-a",
  "descripcion": "Servicio de ejemplo",
  "puertos": [8080],
  "chequeo": {"puerto": 8080, "ruta": "/health"}
}
```

La referencia completa está en [docs/api-v1.md](docs/api-v1.md).

## Seguridad y operación

Detén el contenedor de forma ordenada para que pueda liberar sus direcciones. No reutilices
identificadores VRRP, no uses direcciones del rango DHCP y no compartas cuentas humanas ni
credenciales API entre aplicaciones.

Documentación:

- [Arquitectura](docs/arquitectura.md)
- [Usuarios y 2FA](docs/usuarios-y-2fa.md)
- [Operación y recuperación](docs/operacion-y-recuperacion.md)
- [Modelo de seguridad](docs/modelo-seguridad.md)

## Soporte

El soporte se presta en la comunidad de Discord de Unraides:

https://discord.gg/8MAT6ZGJTW

No publiques contraseñas, tokens ni datos reales de la red al solicitar ayuda.

## Licencia

Código y documentación: [Apache License 2.0](LICENSE).
Los avisos de los componentes incluidos están en
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

