<p align="center">
  <img src="assets/github-banner.svg" alt="Keepalived — VRRP, direcciones flotantes y failover" width="100%">
</p>

<p align="center">
  <img alt="Versión 1.0.7" src="https://img.shields.io/badge/versión-1.0.7-a78bfa">
  <img alt="Un contenedor" src="https://img.shields.io/badge/despliegue-1%20contenedor-55df9a">
  <img alt="VRRP" src="https://img.shields.io/badge/red-VRRP-12cddd">
  <a href="LICENSE"><img alt="Licencia Apache 2.0" src="https://img.shields.io/badge/licencia-Apache--2.0-7d91a3"></a>
</p>

<p align="center"><strong>Una dirección estable para un servicio capaz de cambiar de nodo.</strong></p>

Infraestructura de alta disponibilidad para direcciones IPv4 flotantes. Una dirección
permanece estable para sus clientes y se mueve al nodo que está sirviendo realmente la
aplicación. La versión estable actual es `1.0.7`.

**[Instalación](docs/instalacion.md)** ·
**[Arquitectura](docs/arquitectura.md)** ·
**[API v1](docs/api-v1.md)** ·
**[Operación y recuperación](docs/operacion-y-recuperacion.md)** ·
**[Seguridad](docs/modelo-seguridad.md)**

| | |
|---|---|
| Mecanismo | VRRP con `keepalived` |
| Plataforma | contenedores Linux para servidores `linux/amd64` y `linux/arm64` |
| Producto | panel web, API y keepalived en el mismo contenedor |
| Acceso humano | usuarios, roles, sesiones y TOTP 2FA |
| Acceso de aplicaciones | claves API individuales, revocables y con scopes |
| Adaptador incluido | plantilla y despliegue remoto para Unraid |
| Estado persistente | `pool.json` y `security.json`, con revisión causal y réplica por cuórum |
| Versión actual | `1.0.7` |
| Código y seguimiento | repositorio público `Ezr43l/keepalived-s` |
| Imagen de release | `ghcr.io/ezr43l/keepalived-s:1.0.7` |

## Qué resuelve

- Comprueba cada servicio contra `127.0.0.1` en cada nodo: una máquina encendida con la
  aplicación caída cede la dirección.
- Reparte las VIP de forma determinista y respeta el servidor por defecto elegido por el
  operador.
- Drena nodos en mantenimiento y muestra antes qué servicios quedarían sin respaldo.
- Detecta nodos no accesibles, servicios sin respuesta y una misma VIP en varios portadores.
- Gestiona un pool de direcciones y reclamaciones idempotentes para aplicaciones.
- Protege el panel con cuentas locales y la API con una credencial diferente por aplicación.
- Reconcilia el pool y las credenciales por causalidad y exige una mayoría de identidades
  lógicas antes de confirmar cambios.
- Limita el contrato de la versión 1.0.7 a 64 VIP host-unicast en redes `/24`; nunca acepta
  una VIP igual a la dirección de gestión de un nodo.

## Seguridad

Sólo `GET /api/health` es público. El navegador utiliza una cookie firmada y CSRF; las
aplicaciones presentan `Authorization: Bearer fip_...`; los nodos se autentican mediante HMAC,
nonce anti-replay y sobres cifrados.

Roles disponibles:

- `reader`: consulta;
- `operator`: pool, asignación y mantenimiento;
- `admin`: usuarios, restablecimientos, 2FA y claves API.

Las contraseñas se derivan con `scrypt`; TOTP se cifra en reposo; las claves API y los códigos
de recuperación sólo se guardan como hashes. Las credenciales administrativas sensibles
requieren confirmar la contraseña del administrador y su 2FA, si está activo.

## Instalación rápida en Unraid

1. Descarga [la plantilla pública](unraid/my-Keepalived.xml) y guárdala en
   `/boot/config/plugins/dockerMan/templates-user/`, o impórtala con
   [Zero Launcher](https://github.com/Ezr43l/zero-launcher-s).
2. Selecciónala al añadir un contenedor en Unraid. Sólo solicita el puerto del
   panel (normalmente `6060`) y la carpeta persistente de Keepalived.
3. La plantilla descarga `ghcr.io/ezr43l/keepalived-s:stable` (actualmente
   `1.0.7`). No necesitas crear un registro privado ni construir una imagen.
4. Abre la WebUI y completa el asistente: cuenta inicial, identidad del nodo,
   topología y secretos generados dentro del volumen persistente.
5. Configura las IP flotantes y sus servicios desde el portal. Incorpora los
   demás nodos con los datos del grupo y crea una clave API para cada aplicación.

La configuración funcional también se puede cambiar después desde el portal.
Los puertos, la red host, los montajes y las capacidades siguen perteneciendo
al contenedor. La imagen necesita acceso a la red real del servidor.

La guía completa está en [Instalación](docs/instalacion.md). Los scripts de
manifiestos y despliegue remoto se conservan como herramientas heredadas para
administradores; no son requisitos de la instalación pública mediante plantilla.

`AMD64` y `ARM64` identifican las dos arquitecturas de CPU de las imágenes
Linux. No son versiones para Windows: Docker Desktop sólo se utiliza aquí como
motor de laboratorio; el destino operativo son servidores Docker Linux, con
adaptación específica para Unraid.

Antes de detener un contenedor, el despliegue real descarga copias de sólo lectura de
`pool.json` y `security.json` de todos los miembros y valida esquema, topología, causalidad y
cuórum dentro de la propia imagen candidata Linux, sin red, con raíz de sólo lectura y sin
capacidades. También exige una sola revisión OCI para la cohorte, conserva el `RepoDigest`
inmutable en la plantilla y arranca cada candidato por su ID local `sha256`.

La transacción duradera actualiza siempre la topología completa N/N y conserva journal,
snapshots y barrera `.deploy-freeze`: antes del commit ejecuta rollback coordinado y, una vez
durable el commit, reanuda hacia delante. Estas operaciones del adaptador heredado
requieren ventana de mantenimiento, backup coherente y un procedimiento de reversión
probado. [La validación de 1.0.1](docs/VALIDATION-1.0.1.md) es evidencia histórica,
no una lista de bloqueos pendientes de la versión estable actual.

## API de aplicaciones

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

Repetir la misma operación devuelve la misma IP. Liberarla usa
`DELETE /api/claims/{Idempotency-Key}`. Una clave con `status:read` puede consultar
`GET /api/direcciones`; `claims:write` permite reclamar y liberar. Las claves API no pueden
cambiar usuarios, mantenimiento o servidor preferido.

## Documentación

| Documento | Contenido |
|---|---|
| [Arquitectura](docs/arquitectura.md) | componentes, flujos, persistencia y failover |
| [Instalación](docs/instalacion.md) | manifiesto, secretos, construcción, despliegue y primer acceso |
| [Usuarios y 2FA](docs/usuarios-y-2fa.md) | roles, sesiones, TOTP y recuperación |
| [API v1](docs/api-v1.md) | autenticación, scopes, contratos, errores y migración |
| [Operación y recuperación](docs/operacion-y-recuperacion.md) | mantenimiento, backup, rotación e incidentes |
| [Modelo de seguridad](docs/modelo-seguridad.md) | amenazas, controles, cabeceras y límites |
| [Validación documentada](docs/VALIDATION-1.0.1.md) | builds, pruebas, laboratorio local y escaneo |
| [Checklist de release](docs/RELEASE-CHECKLIST.md) | puertas antes de exportar y publicar |

## Construcción y publicación

`./build-image.sh` construye la imagen en el equipo local. Nosotros preparamos
las imágenes AMD64 y ARM64 y las subimos terminadas a GHCR; GitHub sólo recibe
el código, la documentación y los archivos preparados. No ejecuta tareas
automáticas de construcción ni de comprobación.

La versión actual es `1.0.7`, definida en [VERSION](VERSION). La plantilla de
Unraid apunta a `:stable`, que permite recibir la última versión estable sin
editar la plantilla. La etiqueta `:1.0.7` conserva esa versión concreta.

Para instalar, usa la plantilla pública o Zero Launcher. El Compose del código
sirve para desarrollo; no es obligatorio construir para instalar en Unraid.
Los registros internos son opcionales, nunca un requisito de primer arranque.

El procedimiento vigente está en [Publicación](docs/RELEASE-CHECKLIST.md).
Las comprobaciones se hacen sólo sobre el cambio solicitado y con un máximo
de 20 casos. Los informes de versiones anteriores conservan carácter histórico.

## Soporte

El soporte se presta exclusivamente en la comunidad de Discord de Unraides:

**[Entrar en Unraides](https://discord.gg/8MAT6ZGJTW)**

No se atienden solicitudes de soporte en GitHub. Al pedir ayuda, indica la
versión de la aplicación y el error, sin compartir contraseñas ni tokens.

## Licencia

El código y la documentación propios se distribuyen bajo **Apache License 2.0**. El texto
canónico está en `LICENSE`; por eso la imagen declara
`org.opencontainers.image.licenses=Apache-2.0` y la release pública exige
`LICENSE_SPDX=Apache-2.0`.

La imagen también agrega Keepalived, iproute2 y otras dependencias con sus propias
licencias. No se relicencian bajo Apache-2.0: `THIRD_PARTY_NOTICES.md` documenta su
procedencia, la imagen incluye los textos GPL de Keepalived e iproute2 en
`/opt/licenses`, y cada release aporta el inventario exacto en sus SBOM SPDX por
arquitectura.

## Principios de operación

- Dar `docker stop` antes de eliminar un contenedor para que keepalived pueda soltar las VIP.
- No reutilizar VRID ni incluir VIP dentro del rango DHCP.
- No montar `check-http` desde un sistema que pierda su bit de ejecución.
- No considerar que una SPA está sana por responder HTML genérico con `200`.
- No suponer que VRRP replica datos de la aplicación: sólo mueve direcciones.
- No compartir cuentas humanas ni claves API entre aplicaciones.
- No cambiar el orden de `FIP_NODOS` entre nodos: su primer elemento fija el escritor del
  plano de control.
