# CHANGELOG — Floating IP

La aplicación, la imagen y las recetas de instalación comparten la versión de
[`VERSION`](VERSION). Mientras `1.0.2` no se haya publicado, las correcciones de
su candidata conservan ese número y obligan a reconstruir y repetir todas las
puertas. Después de publicarla, cualquier cambio del runtime requiere una nueva
versión SemVer.

## [1.0.6] - Unreleased

### Fixed

- `libuuid` queda fijado a la revisión corregida `2.42.3-r1`; la imagen vuelve a
  superar la puerta que rechaza vulnerabilidades altas y críticas.
- Las puertas de CI obtienen la versión desde `VERSION` y validan el artefacto real
  antes de permitir su publicación.
- El test del renderer deja de intentar inyectar `FIP_NODO`, que ya no forma parte
  de la plantilla mínima porque la identidad se configura desde el portal.
- Las pruebas de despliegue y sus mensajes consumen la versión actual del proyecto,
  sin acreditar por error un candidato histórico.

## [1.0.5] - Unreleased

### Fixed

- Añadido al pie del panel el enlace autenticado «Ver API JSON» al estado de la API.
- El workflow de CI obtiene la versión de `VERSION` para validar, construir y comprobar la
  imagen, en lugar de conservar una versión anterior incrustada en sus puertas.

## [1.0.4] - Unreleased

### Fixed

- Añadida una sección de configuración reservada a administradores para editar
  desde la aplicación la identidad local, la topología, las URLs de los paneles,
  interfaces, prioridades, retardo, prefijo VIP, duración de sesión, cookie HTTPS
  y emisor TOTP.
- La configuración se valida y persiste atómicamente en `/datos`; cuando cambia,
  el mismo contenedor se reinicia para cargarla sin unidades auxiliares.
- La plantilla de Unraid conserva únicamente el puerto del panel y el volumen
  persistente, que son parámetros propios de Docker.

## [1.0.3] - Unreleased

### Fixed

- La plantilla de Unraid queda reducida al puerto y al volumen persistente.
- El asistente inicial solicita la topologia, genera los tres secretos y entrega
  un codigo de incorporacion para los demas nodos.
- Una instalacion 1.0.2 migra sus variables y secretos al volumen sin sustituir
  el pool, las cuentas ni la configuracion VRRP existentes.

## [1.0.2]

### Fixed

- Anotadas tres expansiones deliberadas de ShellCheck para que la puerta CI
  evalúe correctamente los bloques remotos y las funciones invocadas por `trap`.
- Sustituye la etiqueta pública `v1.0.1`, cuya CI no llegó a superar ShellCheck;
  no se promovió ninguna imagen desde esa etiqueta.

## [1.0.1] - Unreleased

### Candidate

- Candidata inicial del producto, todavía no promovida ni publicada. El commit
  exacto debe superar [la validación 1.0.1](docs/VALIDATION-1.0.1.md) y la
  [checklist de release](docs/RELEASE-CHECKLIST.md).
- Runtime de servidor Linux para `linux/amd64` y `linux/arm64`, orientado a
  Docker y con adaptador específico para Unraid.
- Licencia Apache-2.0 para el código propio; licencias y avisos de las
  dependencias redistribuidas incluidos en la imagen.

### Alta disponibilidad

- Failover VRRP condicionado a la salud real del servicio y reparto de VIP
  entre los nodos disponibles.
- Colocación elegida por el operador, mantenimiento seguro, drenaje y detección
  explícita de una VIP sostenida por más de un nodo.
- Keepalived sólo arranca después de reconciliar el pool con cuórum, validar la
  configuración local y publicar un marcador efímero atómico.
- Anti-entropía periódica para reincorporar nodos sin aplicar una réplica a
  Keepalived hasta que el propio receptor demuestre mayoría.

### Persistencia y clúster

- `pool.json` y `security.json` usan revisiones causales ligadas al estado
  heredado. Las ramas concurrentes, obsoletas o incompatibles fallan cerradas;
  las marcas de tiempo no eligen ganadores.
- El primer elemento de `FIP_NODOS` es el único escritor lógico. Toda mutación
  reconcilia una mayoría de identidades autenticadas antes de autorizar y
  escribir, y exige ACK de identidad y huella antes de informar éxito.
- Una escritura persistida localmente que no logra confirmación de cuórum se
  comunica como commit incierto; el cliente debe consultar antes de reintentar.
- Endpoints internos v2 separados para pool y acceso, con descubrimiento de
  capacidad y sin fallback de escritura hacia nodos antiguos.
- Recuperación de un nodo nuevo desde el snapshot causal dominante sin tratar
  la ausencia de fichero como una rama vacía.
- Esquemas cerrados, límite de 512 KiB, rechazo de JSON ambiguo, enlaces y
  ficheros no regulares, permisos privados y reemplazo atómico con `fsync`.

### Acceso

- Registro de la primera cuenta administradora sin usuario ni contraseña
  predeterminados.
- Usuarios locales, roles `reader`, `operator` y `admin`, sesiones firmadas,
  protección CSRF y cambio obligatorio de contraseñas temporales.
- Contraseñas derivadas con parámetros `scrypt` canónicos y acotados.
- TOTP cifrado, códigos de recuperación de un solo uso y protección de la
  última cuenta administradora.
- Claves API independientes, revocables y limitadas a scopes; sólo
  `/api/health` permanece anónima y no revela topología ni readiness.
- Reconciliación estricta antes de autenticar un login o autorizar cualquier
  mutación, para que una sesión, cuenta o clave revocada no opere desde una
  copia local obsoleta.
- Tráfico interno firmado con ventana temporal y nonce anti-replay; snapshots y
  ACK cifrados y ligados a identidad lógica.

### Instalación y distribución

- Topología, direcciones, servicios, registros opcionales, rutas, claves SSH y
  secretos permanecen fuera del repositorio y de la imagen.
- Compose permite construir localmente sin Registry previo. La plantilla Unraid
  descargará una imagen pública versionada sólo después de su publicación.
- El adaptador de manifiesto genera una única semilla inicial de `pool.json` y
  sólo puede instalarla durante `--fresh-install`, sobre el clúster completo y
  realmente vacío. Una actualización ordinaria o un reemplazo nunca recibe la
  semilla: la ausencia de estado debe resolverse desde el dominante causal de una
  mayoría.
- Preflight de `pool.json` y `security.json` de todos los nodos dentro de la
  propia imagen candidata Linux, sin red, con raíz de sólo lectura y sin
  capacidades, antes de modificar almacenamiento o detener contenedores.
- Resolución previa del `RepoDigest`, arranque por ID local `sha256` y exigencia
  de una misma revisión OCI para toda la cohorte v2.
- Despliegue real transaccional sobre la topología completa N/N, con journal y
  snapshots duraderos, barrera `.deploy-freeze`, contenedor anterior preservado,
  rollback global antes del commit y finalización hacia delante después de una
  decisión de commit duradera.
- Secretos aportados mediante ficheros `_FILE`, montajes de sólo lectura y
  almacenamiento host con permisos root-only fuera de `/boot`.
- Contenedor con raíz de sólo lectura, `cap-drop=ALL`, capacidades mínimas para
  VRRP y su health check, `no-new-privileges`, límite de procesos y `tmpfs`
  acotados.
- Imagen base, paquetes, acciones y herramientas fijados; las puertas incluyen
  tests, laboratorios VRRP de contenedores Linux orquestados desde shell o
  PowerShell, ShellCheck, actionlint, pip-audit,
  Bandit, Gitleaks, Trivy, SBOM y procedencia.

### Puertas abiertas del candidato

- La transacción duradera ya forma parte de `deploy-floating-ip.sh` y dispone de
  pruebas de interrupción por fases. Aún debe superar la auditoría independiente
  final y la puerta física N/N sobre los tres servidores antes de promoverse.
- Continúan pendientes las puertas externas del futuro repositorio público,
  GHCR, atestaciones y GitHub Release inmutable.

## Historial anterior a 1.0.0

Las iteraciones de desarrollo previas introdujeron gradualmente el panel, la API del
pool, reclamaciones idempotentes, colocación y mantenimiento, la interfaz
adaptable, autenticación, empaquetado reproducible y el adaptador Unraid. Esas
revisiones no constituyen releases públicas ni contratos de compatibilidad. La
primera distribución compartida comienza en `1.0.1` una vez superadas todas sus
puertas.
