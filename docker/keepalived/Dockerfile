# Imagen de las direcciones IP flotantes: keepalived y su panel, juntos.
#
# No usamos osixia/keepalived: reescribe el fichero de configuracion al arrancar
# y, montado en solo lectura, muere con «Resource busy». Esta es minima y no
# toca nada.
# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG PYTHON_IMAGE=python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
ARG FIP_APP_VERSION=1.0.6

FROM ${PYTHON_IMAGE} AS runtime-base

ARG FIP_APP_VERSION
ARG BUILD_DATE=""
ARG VCS_REF="unknown"
ARG SOURCE_URL="https://github.com/Ezr43l/keepalived-s"
ARG LICENSE="Apache-2.0"

LABEL org.opencontainers.image.title="Floating IP" \
      org.opencontainers.image.description="Direcciones IPv4 flotantes con Keepalived y panel autenticado" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.version="$FIP_APP_VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="$LICENSE" \
      io.ezr43l.cluster-protocol="v2" \
      io.ezr43l.image.third-party-notices="/opt/THIRD_PARTY_NOTICES.md"

# iproute2 es del panel y curl del chequeo de salud. La imagen base ya está
# fijada por digest: no se hace un `apk upgrade` dependiente del instante. Todo
# paquete adicional queda fijado en el lock y las ruedas Python, por hash.
COPY docker/keepalived/apk-packages.lock /tmp/apk-packages.lock
RUN apk add --no-cache \
      $(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' \
        /tmp/apk-packages.lock) \
    && apk info --license keepalived | grep -Eq '^GPL-2\.0-(only|or-later)$' \
    && apk info --license iproute2 | grep -Fx 'GPL-2.0-or-later' \
    && sed -n '/^P:keepalived$/,/^$/p' /lib/apk/db/installed \
      | grep -Fx 'c:e0fe0621ab32bf73a803d0e7d0c8c084c784dfd2' \
    && sed -n '/^P:iproute2$/,/^$/p' /lib/apk/db/installed \
      | grep -Fx 'c:3ee752ad0c8445c8105177cd5cebdd730789bcd8'
COPY docker/keepalived/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes \
      --requirement /tmp/requirements.txt

# Las imágenes Alpine no conservan necesariamente los textos de licencia de
# cada APK. Se incorporan las copias upstream exactas, fijadas por checksum.
ADD --checksum=sha256:8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643 \
    https://raw.githubusercontent.com/acassen/keepalived/v2.3.4/COPYING \
    /opt/licenses/keepalived-COPYING
ADD --checksum=sha256:e6d6a009505e345fe949e1310334fcb0747f28dae2856759de102ab66b722cb4 \
    https://raw.githubusercontent.com/iproute2/iproute2/v7.0.0/COPYING \
    /opt/licenses/iproute2-COPYING

# El guion de salud va DENTRO de la imagen a propósito. Montado desde /boot no
# sirve: el USB de Unraid es FAT y no guarda el bit de ejecución. Si Keepalived
# desactiva el chequeo, el nodo puede conservar una dirección sin servirla.
COPY docker/keepalived/check-http /usr/local/bin/check-http
COPY docker/keepalived/entrypoint.sh /usr/local/bin/entrypoint
COPY docker/keepalived/panel /opt/panel
COPY LICENSE /opt/LICENSE
COPY THIRD_PARTY_NOTICES.md /opt/THIRD_PARTY_NOTICES.md
RUN chmod 755 /usr/local/bin/check-http /usr/local/bin/entrypoint

# La version del producto se inyecta al construir la imagen y es la unica
# version que muestra el panel.
ENV FIP_APP_VERSION=$FIP_APP_VERSION

ENV FIP_DRENAR=/run/floating-ip/drenar \
    FIP_WEB=/opt/panel/web \
    FIP_DATOS=/datos \
    FIP_PUERTO=6060 \
    FIP_CONF=/datos/keepalived.conf

EXPOSE 6060

# SIN HEALTHCHECK, a proposito. Docker comprueba la salud con un `docker exec`, y en
# estos nodos `dockerd` corre con XDG_RUNTIME_DIR=/run/user/0: runc guarda ahi el estado
# de cada exec y systemd borra esa carpeta cuando root no tiene sesion, con lo que
# CUALQUIER exec falla a ratos. El contenedor salia «unhealthy» con el panel
# respondiendo 200 desde dentro y desde fuera.
#
# Un indicador que miente es peor que no tenerlo. Quien quiera vigilarlo de verdad tiene
# GET /api/health por HTTP, que no pasa por exec y no se inventa nada.

FROM runtime-base AS tests
COPY docker/keepalived/tests /opt/tests
COPY VERSION /src/VERSION
COPY unraid /src/unraid
COPY docker/keepalived/Dockerfile /src/docker/keepalived/Dockerfile
COPY docker/keepalived/apk-packages.lock /src/docker/keepalived/apk-packages.lock
COPY render-unraid-template.py docker-compose.yml .env.example deploy-floating-ip.sh \
    prepare-compose-storage.sh THIRD_PARTY_NOTICES.md /src/
RUN python3 -m unittest discover -s /opt/tests -v \
    && touch /tmp/floating-ip-tests-passed

FROM runtime-base AS runtime
COPY --from=tests /tmp/floating-ip-tests-passed /opt/.tests-passed

ENTRYPOINT ["/usr/local/bin/entrypoint"]
