# CHANGELOG — imagen Floating IP

Este fichero resume los cambios del runtime de contenedor. El historial del
producto completo está en [`../../CHANGELOG.md`](../../CHANGELOG.md) y la
evidencia del candidato exacto en
[`../../docs/VALIDATION-1.0.1.md`](../../docs/VALIDATION-1.0.1.md).

## [1.0.7] - 2026-09-13

- Añadido el enlace de soporte a Unraides en el acceso y en el pie del panel.

## [1.0.6] - Unreleased

- Actualizado `libuuid` a `2.42.3-r1` para eliminar las vulnerabilidades altas
  detectadas en la imagen base.

## [1.0.5] - Unreleased

- Añadido al pie del panel el enlace autenticado al estado JSON de la API.

## [1.0.4] - Unreleased

- Configuración completa y editable desde el panel para administradores.
- Persistencia atómica en `/datos` y reinicio del mismo contenedor al guardar.

## [1.0.3] - Unreleased

- Configuracion inicial y secretos persistentes dentro de `/datos`.
- Migracion automatica y compatible desde las variables de 1.0.2.

## [1.0.1] - Unreleased

### Candidate

- Runtime de servidor Linux para `linux/amd64` y `linux/arm64`, todavía no
  promovido ni publicado.
- Python 3.12 sobre Alpine 3.24 fijado por digest, dependencias Python fijadas y
  licencias de Keepalived e iproute2 incorporadas a la imagen.
- Panel autenticado con usuarios, roles, sesiones firmadas, CSRF, TOTP,
  recuperación y claves API con scopes.
- Revisiones causales de pool y acceso ligadas a su base heredada, escritor
  lógico fijo, cuórum por identidad y commits inciertos explícitos.
- Réplica cifrada mediante endpoints internos v2, sin fallback de escritura a
  runtimes antiguos.
- Recuperación de nodos sin estado y anti-entropía periódica sin aplicar una
  réplica a Keepalived antes de demostrar mayoría.
- Inicialización de `pool.json` y `security.json` ausentes sólo mediante los
  marcadores root-only de un `--fresh-install`; un reemplazo sin estado adopta
  el dominante causal de una mayoría en vez de crear un vacío nuevo.
- Keepalived espera al marcador atómico que acredita pool reconciliado y
  configuración validada.
- Validador offline incluido en la imagen para acreditar esquema, topología,
  causalidad y cuórum de las copias de todos los nodos, ejecutable sin red y con
  el filesystem del contenedor de sólo lectura.
- Soporte del runtime para la barrera root-only `.deploy-freeze`, que cierra las
  mutaciones externas mientras exista y sea exacta. La coordinación duradera que
  debe instalarla, recuperarla y retirarla sigue siendo una puerta del adaptador
  de despliegue; no se considera todavía una garantía de rollback de la release.
- Estado persistente con esquema cerrado, límite de 512 KiB, JSON no ambiguo,
  permisos privados, rechazo de enlaces y reemplazo atómico duradero.
- Root filesystem de sólo lectura, capacidades mínimas, `no-new-privileges`,
  límite de procesos y `tmpfs` acotados.
- Salud pública mínima; topología, readiness y escritor sólo aparecen en estado
  autenticado.
- La construcción ejecuta la suite obligatoria antes de copiar su marcador al
  runtime. CI añade laboratorios VRRP de contenedores Linux orquestados desde
  shell o PowerShell y auditorías de
  dependencias, código, secretos e imagen.

## Historial anterior a 1.0.0

Las iteraciones previas fueron candidatas locales usadas para desarrollar el
chequeo de salud, el panel, la API, el failover, el acceso y el endurecimiento
del contenedor. No son releases públicas ni contratos de compatibilidad.
