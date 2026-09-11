# Instalación y actualización

## Requisitos

- Un host Docker para contenedores Linux. El candidato se construye para
  `linux/amd64` y `linux/arm64`; ambos nombres describen la CPU del servidor, no
  una aplicación para Windows.
- Dos o más servidores en el mismo dominio de broadcast para VRRP.
- Docker con red `host` y capacidades `NET_ADMIN`, `NET_BROADCAST`, `NET_RAW` y
  `SETGID`. Esta última permite que Keepalived prepare el proceso aislado del
  chequeo de salud; no sustituirlas por `--privileged`.
- Acceso a la imagen pública versionada de GHCR o Docker/Buildx para construirla
  localmente desde el código fuente.
- Bash, cliente OpenSSH, `ssh-keygen`, GNU `timeout` y Python 3 estándar sólo si se usa el
  adaptador de despliegue remoto para Unraid. Puede ejecutarse desde un contenedor Linux de
  herramientas aunque el equipo de administración use Docker Desktop.
- Claves SSH dedicadas y un `known_hosts` preparado fuera del repositorio. Cada dirección de
  gestión debe estar fijada de antemano; el adaptador usa comprobación estricta y nunca acepta
  automáticamente una clave de host nueva.
- Relojes de todos los hosts sincronizados mediante NTP/chrony. El adaptador aborta antes de
  mutar el clúster si el desfase supera 30 segundos de forma predeterminada.
- Una carpeta de secretos fuera del repositorio.

Todos los nodos deben recibir la misma lista `FIP_NODOS` (entre 2 y 16 nodos), en el mismo orden, y los tres
secretos idénticos. El primer nombre de esa lista es el escritor fijo del plano de
control. La configuración de cada contenedor se edita desde el panel con una cuenta
administradora. Los valores no están bloqueados, pero todos los miembros deben conservar una
topología coherente; cambiar el escritor de un clúster con estado requiere una migración
coordinada y no se consigue editando un único nodo.

La imagen y Compose son independientes de Unraid. El adaptador incluido genera
plantillas para ese sistema, pero ninguna imagen o plantilla versionada contiene
nombres, direcciones, rutas ni secretos de una instalación concreta.

## 1. Preparar el manifiesto

Copiar `manifiesto.example.sh` fuera del repositorio y definir:

- nodos: nombre, IP de gestión, interfaz, prioridad y fichero SSH;
- hasta 64 direcciones iniciales: nombre, VIP host-unicast, VRID, puerto/ruta de salud y nodo
  preferido opcional; ninguna puede coincidir con la IP de gestión de un nodo;
- inicio del rango DHCP por último octeto y prefijo fijo `/24` en la versión 1.0.6;
- `PREEMPT_DELAY`, entero entre 0 y 1000 segundos, que también se persiste como
  `FIP_RETARDO` en cada contenedor;
- registros por nodo, si no usan el valor predeterminado.

El repositorio carga la ruta mediante `FIP_MANIFIESTO`.

## 2. Generar secretos

```bash
./provision-security-secrets.sh /ruta/privada/secretos
```

El comando crea con modo `0600`, si todavía no existen:

| Fichero | Uso |
|---|---|
| `keepalived-vrrp.txt` | autenticación VRRP, limitada por Keepalived a ocho caracteres |
| `keepalived-session-secret.txt` | firma de sesiones, cifrado TOTP y hash de claves API |
| `keepalived-cluster-token.txt` | autenticación y cifrado entre nodos |

No guardar ninguno de estos valores en Git, documentación, capturas ni incidencias.

## 3. Simular el despliegue

```bash
FIP_MANIFIESTO=/ruta/mi-manifiesto.sh \
FIP_SECRETS_DIR=/ruta/privada/secretos \
FIP_VRRP_AUTH_FILE=/ruta/privada/secretos/keepalived-vrrp.txt \
./deploy-floating-ip.sh --dry-run
```

La simulación valida secretos, IP, VRID, interfaces, prioridades, puertos y rutas sin
conectarse a Docker ni modificar nodos.

## 4. Construir localmente durante el desarrollo

```bash
./build-image.sh
```

Esto crea `keepalived:1.0.6` en Docker local, ejecuta la batería obligatoria y no
publica nada. También puede usarse directamente:

```bash
docker build --file docker/keepalived/Dockerfile \
  --build-arg FIP_APP_VERSION=1.0.6 \
  --tag keepalived:1.0.6 .
```

La plantilla Unraid no construye imágenes: descarga exactamente su campo
`<Repository>`. El destino de la release compartida es
`ghcr.io/ezr43l/keepalived-s:1.0.6`, de modo que una instalación nueva no
necesitará disponer antes de un Registry propio. Mientras esa imagen no esté publicada,
debe construirse desde el código fuente auditado y distribuirse por un registro elegido
por el operador. La publicación sólo se habilita en `Ezr43l/keepalived-s` tras superar la
checklist de release.

Para una instalación estable no se utiliza directamente el XML del árbol ni se copia el tag
anterior. Se descargan de la GitHub Release inmutable `my-Keepalived-1.0.6.xml`,
`docker-compose-1.0.6.yml`, `SHA256SUMS` e `image-digest.txt`. Los dos instaladores generados
contienen exactamente `ghcr.io/ezr43l/keepalived-s@sha256:<digest-del-índice>`; ese digest es
el índice multi-arquitectura atestiguado, no uno de sus manifiestos hijo. Antes de instalar se
verifican la procedencia de `SHA256SUMS` y las sumas de los adjuntos. El Compose de release no
incluye `build:` y, por tanto, tampoco recompila silenciosamente otra imagen.

## 5. Instalar con Compose

1. Copiar `.env.example` a `.env` y sustituir exclusivamente los valores RFC
   5737 por la topología real de ese nodo.
2. Crear `data/` y generar los tres secretos. Si se usa
   `provision-security-secrets.sh`, apuntar `FIP_VRRP_AUTH_FILE`,
   `FIP_SESSION_SECRET_FILE` y `FIP_CLUSTER_TOKEN_FILE` a los tres ficheros que produce;
   los nombres de `.env.example` son sólo rutas locales de ejemplo. Antes de arrancar,
   preparar los bind mounts como root, indicando exactamente esas tres rutas:

   ```bash
   sudo ./prepare-compose-storage.sh --fresh-install \
     ./data /ruta/privada/secretos
   ```

   `--fresh-install` crea dos autorizaciones de bootstrap de un solo uso y se rechaza
   si `data/` contiene cualquier objeto. No volver a usar esa opción en una actualización
   o recuperación. La preparación de permisos es necesaria porque la imagen elimina
   `DAC_OVERRIDE` y `CHOWN`: un `data/`
   propiedad del usuario y con modo `0755` no es escribible por el runtime endurecido.
3. Dejar `data/` sin `pool.json` en una instalación Compose nueva. El escritor inicializa
   un pool vacío cuando alcanza cuórum y genera `keepalived.conf`; las direcciones se añaden
   después desde su panel. No crear a mano una revisión ni copiar un estado de otro clúster.
4. Preparar su `.env` correspondiente en al menos una mayoría de nodos. En dos nodos se
   necesitan ambos; en tres, al menos dos.
5. Ejecutar `docker compose up -d --build` en esos nodos para construir localmente.
   Keepalived espera sin anunciar VIP hasta que el panel reconcilia el pool y publica su
   marcador de preparación. Para usar
   la distribución pública, definir
   `FIP_IMAGE_REPOSITORY=ghcr.io/ezr43l/keepalived-s` y usar la imagen GHCR
   exacta; el bloque `build` queda como ruta verificable desde el código fuente.

Compose monta los secretos como ficheros de sólo lectura y los carga mediante
`FIP_VRRP_AUTH_PASS_FILE`, `FIP_SESSION_SECRET_FILE` y
`FIP_CLUSTER_TOKEN_FILE`. No mezclar una variable directa con su variante
`_FILE`: el arranque falla de forma deliberada.

## 6. Desplegar por nodos en Unraid

Una instalación realmente nueva, con todos los directorios de datos ausentes o vacíos y sin
ningún contenedor previo, se autoriza explícitamente una sola vez:

```bash
./deploy-floating-ip.sh --fresh-install
```

La opción exige el clúster completo, instala dos marcadores root-only y el runtime los consume
únicamente después de materializar y replicar con cuórum los estados iniciales. No usarla para
actualizar, recuperar ni sustituir discos: si desaparece el estado, el arranque se cierra en vez
de interpretar la pérdida como una instalación nueva.

Tanto la primera migración desde un clúster antiguo como cualquier actualización o reemplazo
posterior se ejecutan sobre la **topología completa N/N**. Un despliegue real con sólo parte de
los nombres se rechaza antes de mutar. Deben estar disponibles todos los nodos y debe
programarse una ventana de mantenimiento con indisponibilidad planificada, también en
clústeres de tres o más miembros:

```bash
FIP_IMAGE_DIGEST='sha256:<digest-multiarch-de-image-digest.txt>' \
  ./deploy-floating-ip.sh
```

Omitir los nombres procesa exactamente todos los nodos declarados. El digest es obligatorio y
se obtiene de la release verificada; una etiqueta no decide por sí sola qué bytes se ejecutan.
`FIP_REGISTROS_POR_NODO` sólo se usa como override explícito para mirrors privados; si una
entrada no existe, no se inventa un Registry en la IP del nodo. El coordinador detiene
ordenadamente la cohorte, limpia VIP huérfanas, personaliza copias de las plantillas y verifica
paneles, revisiones e identidad de imagen antes de decidir el commit.

El coordinador combina el repositorio configurado con `FIP_IMAGE_DIGEST`, comprueba el
`RepoDigest` devuelto por cada Registry después del `pull` y arranca por el ID local `sha256`
de la variante Linux correspondiente a la CPU del host. La puerta exige una única revisión OCI
en toda la cohorte. No se acepta un digest hijo exclusivo de AMD64 o ARM64: debe usarse el
digest del índice multi-arquitectura consignado en `image-digest.txt`.

Antes de cualquier `pull`, cambio de permisos o parada, el adaptador consulta todos los nodos:
verifica que el escritor lógico no haya cambiado y compara, por huella, los secretos locales con
los ficheros, montajes o variables todavía activos. Una diferencia aborta sin rotar nada. La
rotación de VRRP, sesiones o clúster es una operación coordinada de mantenimiento distinta del
despliegue transaccional ordinario.

Después de esa auditoría de sólo lectura, el adaptador copia `pool.json` y `security.json` de
todos los nodos, resuelve la imagen candidata también en el escritor y ejecuta dentro de ella
el preflight causal. El contenedor temporal funciona con `--network=none`, rootfs de sólo
lectura, `cap-drop=ALL`, `no-new-privileges` y un `tmpfs` acotado; valida esquema, topología,
revisión dominante y cuórum sin consultar la red. El host de administración sólo prepara el
manifiesto JSON con Python estándar. Un fallo aborta antes de normalizar permisos o detener
contenedores.

Durante `--fresh-install`, el manifiesto produce una única semilla inicial de `pool.json`
con las direcciones declaradas y la distribuye byte a byte. Una actualización ordinaria o un
nodo de reemplazo **nunca** recibe esa semilla: si su fichero falta, debe adoptar el dominante
causal de una mayoría. Un `pool.json` previo se valida y preserva. Por tanto, cambiar el
manifiesto después del primer arranque no modifica el pool vivo: esos cambios se realizan
desde el panel del escritor.

En un clúster de dos nodos, el único miembro materializado no constituye una mayoría: un
reemplazo vacío no puede adoptar estado automáticamente. Hay que restaurar primero en el
reemplazo una copia coherente de `pool.json` y `security.json`, con sus secretos asociados, o
recuperar el segundo volumen original. No usar `--fresh-install` ni recrear los marcadores de
bootstrap para sortear esa protección.

El adaptador transfiere los tres valores por la entrada estándar de SSH, crea
ficheros root-only bajo `${FIP_REMOTE_SECRETS_DIR:-/mnt/user/appdata/floating-ip-secrets}`
y monta ese contenido de sólo lectura. Ni `docker inspect` ni la plantilla viva
contienen los valores. No sitúe `FIP_REMOTE_SECRETS_DIR` bajo `/boot`: el sistema
de ficheros del USB de Unraid no conserva los permisos requeridos.
Por la misma razón, `FIP_DATA_DIR` tampoco puede estar bajo `/boot`: el fichero
`keepalived.conf` persistente contiene la clave de autenticación VRRP. Los valores
predeterminados son dos árboles hermanos: datos en `/mnt/user/appdata/floating-ip` y
secretos en `/mnt/user/appdata/floating-ip-secrets`. El adaptador rechaza cualquier
igualdad o anidamiento entre ambos para impedir que `/datos` eluda un montaje `:ro`.

Pool y acceso se replican exclusivamente mediante endpoints internos causales v2. No hay
fallback de escritura hacia un nodo antiguo: esos miembros no cuentan como capaces ni reciben
snapshots nuevos. La primera migración actualiza la cohorte completa dentro de la misma
transacción y no reanuda mutaciones hasta comprobar reconciliación y propiedad exclusiva de
cada VIP. Cuando todas las identidades han demostrado ambas capacidades, el runtime persiste
`.cluster-protocol-v2`, ligado a la lista ordenada de nodos, y no vuelve a habilitar fallbacks
antiguos.

### Transacción y recuperación del despliegue

`deploy-floating-ip.sh` integra el journal duradero, snapshots de todos los nodos, barrera
`.deploy-freeze`, preservación del contenedor anterior, decisión de commit y rollback
coordinado. La preparación queda publicada en todos los miembros antes de mutar. La plantilla
definitiva sólo se instala después de una decisión de commit duradera.

Si el proceso se interrumpe antes del commit, la siguiente invocación detiene la cohorte,
restaura todos los snapshots y reinicia los contenedores anteriores. Si se interrumpe después
del commit, completa hacia delante la plantilla y la limpieza, dejando el escritor lógico para
el final. Este principio de «commit gana» evita que distintos nodos interpreten de forma opuesta
la misma operación.

La recuperación se ejecuta antes de auditar residuos para reconocer preparaciones, candidatos,
renames de plantilla y limpiezas parciales legítimas. No borrar a mano `.deploy-freeze`,
journals, snapshots, temporales reconocidos ni contenedores de rollback. Conservar además un
backup externo coherente y realizar la operación dentro de una ventana asistida hasta superar
la puerta física documentada para el digest exacto.

## 7. Primer acceso

1. Confirmar una mayoría disponible y abrir `http://IP_DEL_ESCRITOR:6060/`, donde el
   escritor es el primer nombre de `FIP_NODOS`.
2. Elegir el nombre de usuario del primer administrador.
3. Escribir y confirmar la contraseña definitiva de esa cuenta.
4. Configurar 2FA y guardar los diez códigos de recuperación.
5. Crear una clave API distinta para cada aplicación.

No hay usuario ni contraseña predeterminados, ni un secreto de primer acceso en un fichero.
La primera cuenta se crea como `admin`, cierra el registro y debe quedar confirmada por cuórum
antes de responder con éxito. El registro y todas las mutaciones posteriores de usuarios,
2FA, claves API y pool se realizan en el escritor. Los demás nodos pueden autenticar y servir
lecturas tras reconciliarse, pero rechazan escrituras con un error de escritor requerido. A
partir de ese momento sólo un administrador autenticado puede crear otras cuentas.

## Variables de seguridad

| Variable | Valor recomendado |
|---|---|
| `FIP_SESSION_SECRET` | entrada local del adaptador; aleatorio base64url, 32 caracteres o más |
| `FIP_CLUSTER_TOKEN` | entrada local del adaptador; aleatorio base64url, 32 caracteres o más |
| `FIP_SESSION_SECRET_FILE` | ruta del fichero dentro del contenedor; preferida a la variable directa |
| `FIP_CLUSTER_TOKEN_FILE` | ruta del fichero dentro del contenedor; preferida a la variable directa |
| `FIP_VRRP_AUTH_PASS_FILE` | ruta del fichero de la clave VRRP dentro del contenedor |
| `FIP_REMOTE_SECRETS_DIR` | carpeta persistente root-only en cada host Unraid; nunca bajo `/boot` |
| `FIP_DATA_DIR` | datos y configuración persistentes; use `/mnt/user/appdata/floating-ip`, nunca `/boot` |
| `FIP_RETARDO` / `PREEMPT_DELAY` | mismo entero de 0 a 1000 segundos en runtime y manifiesto |
| `FIP_CLUSTER_CA_FILE` | CA privada opcional para pares HTTPS |
| `FIP_SESSION_HOURS` | `12` |
| `FIP_COOKIE_SECURE` | `1` con HTTPS; `0` para HTTP directo |
| `FIP_TOTP_ISSUER` | nombre reconocible de la instalación |

El adaptador de la versión 1.0.6 **no rota en sitio** ninguno de los tres secretos: una huella
distinta aborta antes de detener contenedores. Cambiar `FIP_SESSION_SECRET` invalida sesiones
y deja sin posibilidad de descifrado/verificación los TOTP y claves API existentes; requiere
una migración explícita con reenrolado de credenciales. `FIP_CLUSTER_TOKEN` exige congelar
mutaciones y coordinar todos los miembros; la clave VRRP exige una ventana coordinada para
evitar dos dominios de elección. No sustituir ficheros manualmente ni nodo a nodo. La operación
normal es restaurar el material correcto desde backup; cualquier rotación planificada queda
fuera de la automatización de despliegue de esta release.
