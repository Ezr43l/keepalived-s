# Avisos de terceros

El código, la documentación, el panel y los scripts propios de Floating IP se
distribuyen bajo Apache-2.0, conforme al fichero `LICENSE`. La imagen OCI es una
distribución colectiva que también contiene programas y bibliotecas de terceros;
Apache-2.0 no sustituye ni modifica sus licencias.

## Componentes principales incluidos en la imagen

| Componente | Procedencia | Licencia declarada |
| --- | --- | --- |
| Keepalived `2.3.4-r2` | paquete oficial de Alpine Linux | `GPL-2.0-only` en los metadatos APK; el proyecto upstream permite GPL v2 o posterior e incluye una excepción para OpenSSL |
| iproute2 `7.0.0-r0` | paquete oficial de Alpine Linux | `GPL-2.0-or-later` |
| curl | paquete oficial de Alpine Linux | `curl` |
| ca-certificates | paquete oficial de Alpine Linux | `MPL-2.0 AND MIT` |
| cryptography | wheel de PyPI fijada en `requirements.txt` | `Apache-2.0 OR BSD-3-Clause` |
| cffi | wheel de PyPI fijada en `requirements.txt` | `MIT-0` |
| pycparser | wheel de PyPI fijada en `requirements.txt` | `BSD-3-Clause` |
| qrcode | wheel de PyPI fijada en `requirements.txt` | licencia BSD indicada por el proyecto |

La lista anterior destaca las dependencias directas. Cada release adjunta dos
SBOM SPDX JSON, uno por arquitectura, que constituyen el inventario exacto de
paquetes y versiones de la imagen publicada.

La imagen conserva copias literales de los términos GPL suministrados por los
proyectos en:

- `/opt/licenses/keepalived-COPYING`
- `/opt/licenses/iproute2-COPYING`

Fuentes correspondientes y metadatos de empaquetado:

- Keepalived 2.3.4: <https://github.com/acassen/keepalived/tree/v2.3.4>
- Empaquetado Alpine exacto de Keepalived (commit del APK `e0fe0621ab32bf73a803d0e7d0c8c084c784dfd2`): <https://gitlab.alpinelinux.org/alpine/aports/-/tree/e0fe0621ab32bf73a803d0e7d0c8c084c784dfd2/community/keepalived>
- iproute2 7.0.0: <https://github.com/iproute2/iproute2/tree/v7.0.0>
- Empaquetado Alpine exacto de iproute2 (commit del APK `3ee752ad0c8445c8105177cd5cebdd730789bcd8`): <https://gitlab.alpinelinux.org/alpine/aports/-/tree/3ee752ad0c8445c8105177cd5cebdd730789bcd8/main/iproute2>
- Índice de paquetes Python: <https://pypi.org/>

Los binarios de Keepalived e iproute2 se instalan sin modificaciones desde los
repositorios oficiales de Alpine. El build fija tanto la revisión del paquete
como el commit de `aports` declarado dentro del APK, por lo que falla en vez de
aceptar silenciosamente una reconstrucción distinta con el mismo nombre. Para el
resto del inventario exacto se deben consultar los SBOM y el digest inmutable de
la imagen. Los avisos, autores y condiciones de cada componente siguen
perteneciendo a sus respectivos titulares.
