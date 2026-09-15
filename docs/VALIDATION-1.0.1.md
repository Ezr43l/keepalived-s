# Validación de Floating IP 1.0.1

Fecha de revisión documental: 2026-09-01.

## Estado

**Candidato en desarrollo: no promovido, no publicado y todavía no apto para release.**

El árbol actual cambia el contrato de persistencia, reconciliación, arranque y migración. Por
ese motivo no se reutilizan IDs de imagen, recuentos de tests ni resultados de un candidato
anterior. La evidencia final se registrará aquí sólo después de fijar un commit único, construir
ambas arquitecturas desde él y ejecutar todas las puertas sobre esos artefactos exactos.

No existe todavía una imagen pública aprobada en
`ghcr.io/ezr43l/floating-ip-s:1.0.1`. Una etiqueta local con el mismo número de versión no es
evidencia de promoción.

## Contrato que debe validarse

- Runtime de servidor Linux para `linux/amd64` y `linux/arm64`; no son builds de Windows.
- El primer elemento de `FIP_NODOS` es el único escritor de pool y acceso.
- Pool y credenciales usan revisiones causales, selección de un único dominante y cuórum de
  identidades lógicas autenticadas.
- Las réplicas usan endpoints internos v2 con descubrimiento de capacidad y sin fallback de
  escritura a nodos antiguos.
- Keepalived no arranca hasta que el pool queda reconciliado y la configuración local validada.
- El despliegue por manifiesto instala una semilla inicial idéntica exclusivamente con
  `--fresh-install`, sobre el clúster completo realmente vacío; una actualización o reemplazo
  nunca crea esa semilla. Una instalación Compose nueva comienza con un pool vacío.
- Antes de cambiar permisos o detener contenedores, las copias de estado de todos los nodos se
  validan dentro de la imagen candidata Linux con red desactivada, rootfs de sólo lectura y
  capacidades eliminadas.
- Cada candidato debe acreditar versión `1.0.1`, protocolo v2, una misma revisión OCI en la
  cohorte, `RepoDigest` inmutable e ID local `sha256`.
- Todo despliegue real debe operar sobre la topología completa N/N, con journal, snapshots,
  freeze, rollback global antes del commit y finalización hacia delante después del commit.
- `GET /api/health` conserva una respuesta pública mínima sin topología, readiness ni estado
  de acceso.

## Puertas del candidato exacto

| Puerta | Estado | Evidencia que debe conservarse |
| --- | --- | --- |
| Commit privado fijado y árbol limpio exportable | pendiente | SHA y diff revisado |
| Suite completa de tests dentro del build AMD64 | pendiente | log y digest de imagen |
| Suite completa de tests dentro del build ARM64 | pendiente | log y digest de imagen |
| Compose, XML Unraid, renderer, scripts y workflows | pendiente | validadores y logs |
| `pip-audit`, Bandit y Gitleaks | pendiente | versión de herramienta y salida completa |
| Trivy AMD64 sin vulnerabilidades críticas/altas, sin ocultar `unfixed` | pendiente | informe y digest |
| Trivy ARM64 sin vulnerabilidades críticas/altas, sin ocultar `unfixed` | pendiente | informe y digest |
| Metadatos OCI, licencia, avisos, SBOM y ausencia de fuentes de test en runtime | pendiente | inspección de ambas imágenes |
| Arranque endurecido y lectura de secretos mediante `_FILE` | pendiente | inspección y pruebas negativas |
| Pool y `security.json`: límites, esquema cerrado, enlaces, permisos y fallos de `fsync` | pendiente | tests de almacenamiento |
| Escritor fijo, cuórum, causalidad, anti-entropía y commits inciertos | pendiente | tests unitarios e integración de tres nodos |
| Nodo nuevo sin estado recuperado desde una mayoría inicializada; rechazo seguro con un único superviviente en dos nodos | pendiente | pruebas de reemplazo en clústeres de dos y tres nodos |
| Nodo antiguo simulado: cero `POST` a rutas legacy | pendiente | traza de llamadas del test mixto |
| Semilla de manifiesto: sólo `--fresh-install` completo/vacío; actualización y reemplazo no la instalan | pendiente | dry-run y pruebas efímeras positivas/negativas |
| Preflight causal dentro de la imagen candidata, sin red/read-only, antes de permisos y paradas | pendiente | pruebas de estados dominantes, ausentes, concurrentes, truncados y con esquema inválido |
| `RepoDigest`, ID local, versión, protocolo y revisión única de la cohorte | pendiente | inspección y pruebas con tags/digests divergentes |
| Transacción duradera de todos los nodos: freeze, snapshots, commit, rollback y recuperación tras interrupción | pendiente | inyección de fallo en cada fase y ausencia de residuos |
| Laboratorios VRRP sobre contenedores Linux, orquestados desde shell y PowerShell: propiedad exclusiva, drenaje, preempción y split-brain inducido/restaurado | pendiente | logs de ambos laboratorios |
| Instalación Compose desde cero, pool vacío y primer registro en el escritor | pendiente | procedimiento y estado final |

## Puerta física Linux/Unraid

La validación local no sustituye esta puerta. Con las mutaciones congeladas y copias
verificadas, debe probarse el mismo candidato en los tres nodos de destino:

1. repetir salud de aplicaciones, portadores exclusivos y capacidad de sucesión antes de
   modificar nada, y declarar la indisponibilidad planificada de la ventana N/N;
2. ejecutar las puertas externas de sólo lectura en los tres nodos y acreditar el mismo digest
   multi-arquitectura, revisión, topología, secretos y reloj;
3. inyectar un fallo anterior al commit y demostrar rollback completo desde los snapshots, sin
   borrar manualmente journals, barreras ni marcadores;
4. reanudar con una invocación nueva y demostrar que la recuperación no confunde la transacción
   anterior con un despliegue nuevo;
5. completar la migración conjunta N/N y verificar que la limpieza termina con el escritor;
6. probar drenaje, parada, reincorporación, caída de backend y split-brain controlado;
7. restaurar la propiedad exclusiva y comparar las revisiones causales de pool y acceso, las
   plantillas instaladas y los IDs/digests reales de los tres contenedores.

Hasta que esta puerta figure como superada con evidencia del digest exacto, la versión sigue
siendo candidata aunque todos los tests locales pasen.

## Puertas de publicación posteriores

La validación tampoco crea el repositorio público, publica imágenes, genera tags ni releases.
Tras superar todo lo anterior aún quedan la publicación en `Ezr43l/keepalived-s`, el
pull anónimo desde GHCR, la verificación de enlaces públicos, HTTPS real y una instalación
desde cero usando exclusivamente artefactos compartidos.
