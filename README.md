<p align="center">
  <img src="assets/github-banner.svg" alt="Keepalived — VRRP, direcciones flotantes y failover" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Ezr43l/keepalived-s/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Ezr43l/keepalived-s/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Versión 1.0.7" src="https://img.shields.io/badge/versión-1.0.7-a78bfa">
  <img alt="Un contenedor" src="https://img.shields.io/badge/despliegue-1%20contenedor-55df9a">
  <img alt="VRRP" src="https://img.shields.io/badge/red-VRRP-12cddd">
  <a href="LICENSE"><img alt="Licencia Apache 2.0" src="https://img.shields.io/badge/licencia-Apache--2.0-7d91a3"></a>
</p>

<p align="center"><strong>Una dirección estable para un servicio capaz de cambiar de nodo.</strong></p>

Infraestructura de alta disponibilidad para direcciones IPv4 flotantes. Una dirección
permanece estable para sus clientes y se mueve al nodo que está sirviendo realmente la
aplicación. `1.0.7` es la única versión publicada en este repositorio.

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

## Inicio rápido

1. Copiar [`manifiesto.example.sh`](manifiesto.example.sh) fuera del repositorio.
2. Generar los secretos:

   ```bash
   ./provision-security-secrets.sh /ruta/privada/secretos
   ```

3. Validar sin tocar servidores:

   ```bash
   FIP_MANIFIESTO=/ruta/mi-manifiesto.sh \
   FIP_SECRETS_DIR=/ruta/privada/secretos \
   FIP_VRRP_AUTH_FILE=/ruta/privada/secretos/keepalived-vrrp.txt \
   ./deploy-floating-ip.sh --dry-run
   ```

4. Para una instalación Compose nueva, preparar los bind mounts una sola vez:

   ```bash
   sudo ./prepare-compose-storage.sh --fresh-install \
     ./data /ruta/privada/secretos
   ```

5. Durante el desarrollo local, construir con `./build-image.sh`.
6. Instalar con Compose o, en un clúster Unraid realmente nuevo y vacío, autorizar el alta
   completa una sola vez:

   ```bash
   FIP_MANIFIESTO=/ruta/mi-manifiesto.sh \
   FIP_SECRETS_DIR=/ruta/privada/secretos \
   ./deploy-floating-ip.sh --fresh-install
   ```

   Las actualizaciones posteriores no usan `--fresh-install`; siguen el procedimiento de
   [`deploy-floating-ip.sh`](deploy-floating-ip.sh) descrito en la guía de instalación. La
   semilla del manifiesto pertenece exclusivamente a esa alta inicial: una actualización o
   un nodo de reemplazo sin `pool.json` debe recuperar el dominante causal de una mayoría.
7. Con una mayoría de nodos disponible, abrir el panel del primer nodo declarado en
   `FIP_NODOS` y registrar la primera cuenta administradora con su contraseña definitiva.
8. Activar 2FA y crear una clave distinta para cada aplicación.

La topología, los registros, las IP, los servicios, las claves SSH y todos los secretos viven
fuera del repositorio y de la imagen.

El primer elemento de `FIP_NODOS` es el escritor lógico del plano de control. Las altas,
reclamaciones, cambios de mantenimiento, usuarios y claves API se envían a ese nodo; el resto
continúa atendiendo lecturas y participando en VRRP. Esta restricción evita ramas concurrentes
sin impedir que las VIP hagan failover si el escritor no está disponible.
Su identidad y el orden completo de la lista forman parte del estado persistente: el adaptador
rechaza un cambio de escritor antes de detener contenedores.

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
durable el commit, reanuda hacia delante. La candidata sigue pendiente de auditoría final y de
la puerta física descrita en [la validación documentada](docs/VALIDATION-1.0.1.md); hasta superarlas se
requiere ventana de mantenimiento, backup coherente y un procedimiento de reversión probado.

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

```bash
./build-image.sh
```

El comando construye `keepalived:1.0.7` en la máquina local y no publica nada.
`build-image.sh` sólo admite carga local con `--load` y rechaza cualquier flujo de push. La
publicación se realiza exclusivamente mediante el workflow protegido del repositorio público.

El Dockerfile está configurado para ejecutar toda la batería obligatoria antes de producir
cualquier runtime. La
imagen y el panel muestran la versión de [`VERSION`](VERSION), que se mantiene
deliberadamente en `1.0.7`.

El XML y el Compose guardados en el árbol son fuentes de desarrollo. La release pública genera
`my-Keepalived-1.0.7.xml` y `docker-compose-1.0.7.yml` como adjuntos separados: ambos apuntan a
la misma imagen multi-arquitectura mediante `@sha256`, y el Compose distribuido no conserva
`build:`. Una instalación estable debe descargar esos adjuntos, `SHA256SUMS` e
`image-digest.txt` desde la release inmutable; no debe convertir por su cuenta la etiqueta
`:1.0.7` ni copiar un digest hijo exclusivo de AMD64 o ARM64.

La imagen usa Python 3.12 sobre Alpine 3.24 fijada por digest y dependencias
Python fijadas mediante wheels, incluida `cryptography 50.0.1`. Las puertas de CI
incluyen tests, `pip-audit`, Bandit, Gitleaks y Trivy sin ignorar vulnerabilidades no
corregidas. Los laboratorios reproducibles de `docker/keepalived/tests` comprueban VRRP
real, drenaje, preempción y split-brain sobre contenedores Linux; el script PowerShell es
sólo un orquestador de laboratorio, no un runtime Windows. Los resultados del candidato
exacto se registran en [la validación documentada](docs/VALIDATION-1.0.1.md); no se considera publicado
ni promovido mientras quede una puerta pendiente.

Los registros internos siguen admitidos como una configuración opcional del
despliegue; nunca son requisito para instalar desde cero ni valor predeterminado
del producto compartido.

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
