# Seguridad

No publique vulnerabilidades, credenciales ni datos de una instalación en una
incidencia abierta. En el repositorio compartido utilice **Security > Report a
vulnerability** para abrir un aviso privado de GitHub. Si ese canal no estuviera
disponible, contacte al mantenedor por un medio privado antes de compartir detalles.

Incluya la versión, arquitectura, forma de instalación y pasos mínimos de
reproducción. No adjunte `security.json`, `pool.json`, manifiestos reales,
cookies, claves API, tokens de clúster, claves VRRP ni claves SSH.

La imagen no debe exponerse directamente a Internet. El panel se opera en una
red de administración; si atraviesa redes no confiables debe publicarse mediante
HTTPS, activar `FIP_COOKIE_SECURE=1` y usar HTTPS también entre pares.
