# Checklist de publicación de Keepalived 1.0.7

El código, la validación y la publicación pertenecen al repositorio público
`Ezr43l/keepalived-s`. Sólo una versión estable aprobada puede publicarse.

## Puertas pendientes

- [ ] Ejecutar externamente `PUT` + `GET /repos/{owner}/{repo}/immutable-releases`
  con permisos de administración y, sólo tras confirmar `enabled=true`, fijar
  `IMMUTABLE_RELEASES_ENABLED=true`. El workflow no almacena ningún PAT y
  comprueba de nuevo `immutable=true` tras publicar.

- [x] Adoptar Apache-2.0 y añadir el texto canónico en `LICENSE`.
- [x] Separar la licencia del código propio de las licencias de la imagen agregada,
  incorporar los textos GPL de Keepalived/iproute2 y documentar las fuentes en
  `THIRD_PARTY_NOTICES.md`.
- [x] Migrar la plantilla y el adaptador de despliegue a secretos por fichero,
  con rutas genéricas, permisos root-only y sin valores en `docker inspect`.
- [ ] Cerrar el candidato en un único commit y actualizar
  `VALIDATION-1.0.7.md` con resultados de ese SHA exacto, sin heredar IDs ni
  recuentos de otro árbol.
- [ ] Ejecutar la suite completa y construir desde ese commit las imágenes Linux
  AMD64 y ARM64.
- [ ] Probar escritor fijo, cuórum por identidad, causalidad, anti-entropía,
  commits inciertos y recuperación de un nodo sin estado para pool y acceso.
- [ ] Demostrar en una prueba mixta que un nodo antiguo recibe cero `POST` del
  protocolo v2 y no cuenta para su cuórum.
- [ ] Probar la semilla de manifiesto: misma huella en todos los nodos, creación
  exclusivamente con `--fresh-install` sobre el clúster completo y vacío;
  ninguna actualización ni reemplazo puede instalarla.
- [ ] Probar que un reemplazo sin estado adopta el dominante causal de una
  mayoría y que, en dos nodos, un único superviviente no puede inicializarlo:
  exige restaurar antes una copia coherente.
- [ ] Probar una instalación Compose nueva con pool vacío, arranque bloqueado
  hasta cuórum y primer administrador registrado exclusivamente en el escritor.
- [ ] Probar que un cuórum de volúmenes ausentes sin marcadores falla cerrado y que
  `--fresh-install` sólo funciona sobre el clúster completo realmente vacío.
- [ ] Probar separación entre `/datos` y secretos, permisos root-only y rechazo de symlinks,
  hardlinks y rutas anidadas tanto en Compose como en Unraid.
- [ ] Probar los límites de 16 nodos y 64 VIP, `/24`, host-unicast, retardo 0-1000
  y rechazo de colisiones con IP de gestión.
- [ ] Probar que el preflight valida esquema, topología, causalidad y cuórum de
  todos los estados dentro de la imagen candidata Linux, con `--network=none`,
  rootfs read-only, capacidades eliminadas y antes de cambiar permisos o detener
  ningún contenedor.
- [ ] Probar `RepoDigest` inmutable, arranque por ID local `sha256`, etiquetas de
  versión/protocolo/revisión y una única revisión para toda la cohorte v2.
- [ ] Integrar en `deploy-floating-ip.sh` la transacción duradera de clúster:
  journal root-only, snapshots de todos los nodos, barrera `.deploy-freeze`,
  preservación del contenedor previo, decisión de commit y rollback coordinado.
- [ ] Demostrar que un candidato fallido recupera estados, plantillas y
  contenedores previos sin dejar VIP, journals ni marcadores residuales, y que
  una decisión de commit duradera siempre gana durante la reanudación.
- [ ] Inyectar fallos en cada fase de `--fresh-install` y demostrar reanudación o
  limpieza exacta sin confundir un alta parcial con pérdida de volúmenes.
- [ ] Confirmar que `/api/health` sólo expone liveness y versión, y que el estado
  de escritor/readiness requiere sesión.
- [ ] Auditar repositorio, plantillas, documentación, historial exportable y
  metadatos para nombres, hosts, IP, rutas, registros o secretos privados.
- [ ] Configurar la variable del repositorio público `LICENSE_SPDX=Apache-2.0`.
- [ ] Confirmar que `Ezr43l/keepalived-s` conserva únicamente referencias públicas.
- [ ] Publicar desde un árbol limpio y el commit aprobado.
- [ ] Publicar `ghcr.io/ezr43l/keepalived-s:1.0.7` para AMD64/ARM64 con SBOM,
  procedencia y digest.
- [ ] Verificar pull anónimo y todos los enlaces de la plantilla pública.
- [ ] Ejecutar Trivy y Gitleaks de nuevo sobre el artefacto exportado.
- [ ] Ejecutar sobre el candidato exacto los laboratorios VRRP de contenedores
  Linux orquestados desde shell y PowerShell: propiedad exclusiva, drenaje,
  preempción, caída del maestro, split-brain inducido y restauración exacta.
- [ ] Probar VRRP real en al menos dos hosts Linux/Unraid del mismo dominio de
  broadcast: elección, caída de servicio, drenaje, recuperación, split-brain y
  liberación de VIP al parar el contenedor.
- [ ] Probar backup y restauración conjunta de `pool.json`, `security.json`,
  secretos y configuración Keepalived, incluida la recuperación de un nodo nuevo
  desde la mayoría causal.
- [ ] Validar HTTPS, `FIP_COOKIE_SECURE=1` y, si procede, una CA privada entre
  pares mediante `FIP_CLUSTER_CA_FILE`.
- [ ] Instalar desde cero usando sólo artefactos y documentación públicos.

## Contrato inmutable de esta release

1. La versión permanece exactamente `1.0.7` en `VERSION`, imagen, Compose,
   panel y plantilla.
2. Sólo el workflow protegido del repositorio público puede publicar artefactos.
3. La plantilla pública no contiene valores de una instalación y apunta a
   `Ezr43l/keepalived-s`.
4. La instalación nueva no depende de un Registry local; los mirrors internos
   son overrides opcionales.
5. El workflow rechaza licencia ausente, tag divergente, repositorio incorrecto
   y cualquier vulnerabilidad crítica o alta, tenga o no corrección disponible.
6. AMD64 y ARM64 son arquitecturas CPU de una misma aplicación de servidor
   Linux; no se publica ni documenta un runtime nativo para Windows.
7. El orden de `FIP_NODOS`, y por tanto su primer nodo escritor, forma parte de la
   configuración coherente del clúster y es idéntico en todos sus miembros.
