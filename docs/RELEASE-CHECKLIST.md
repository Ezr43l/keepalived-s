# Publicación de Keepalived

Procedimiento vigente desde el 15 de septiembre de 2026. Sustituye el antiguo
proceso de publicación automática y sus requisitos de tareas en GitHub.

## Versión actual

- Versión: `1.0.7`.
- Desarrollo privado: `Ezr43l/keepalived`.
- Distribución pública: `Ezr43l/keepalived-s`.
- Imagen por versión: `ghcr.io/ezr43l/keepalived-s:1.0.7`.
- Canal de la plantilla: `ghcr.io/ezr43l/keepalived-s:stable`.

## Pasos para una modificación

1. Aplicar únicamente el cambio solicitado en el proyecto privado.
2. Para cambios de código, asignar la versión acordada en `VERSION` y actualizar
   el historial y las referencias de versión afectadas.
3. Comprobar la parte modificada y sus dependencias directas: máximo 20 pruebas
   concretas, realizadas en nuestros equipos, no en GitHub.
4. Si cambia el código de la imagen, construir aquí o en nuestros servidores
   las variantes Linux AMD64 y ARM64 necesarias. No recompilar por cambios sólo
   documentales, de soporte o del nombre de un repositorio.
5. Publicar el código terminado en los repositorios privado y público, sin
   copiar al público el historial privado, credenciales ni datos de instalación.
6. Subir a GHCR las imágenes ya construidas, conservar su etiqueta de versión
   y actualizar el canal aprobado. RTFM usa `dev`; las demás usan `stable`.
7. Crear la ficha de versión en GitHub desde el cambio aprobado. Una ficha o
   una subida no debe iniciar ninguna tarea automática.
8. Sincronizar los tres Gitea y comprobar que cada espejo apunta exactamente
   al mismo cambio que el repositorio privado de GitHub.
9. Si hay una imagen nueva, probarla primero en Khonshu y, tras aprobación,
   desplegar esa misma imagen en los tres servidores y comprobar lo afectado.

GitHub es un destino pasivo: no construye, prueba, analiza ni prepara versiones.
Sus tareas automáticas permanecen desactivadas. Las imágenes anteriores y sus
etiquetas no se eliminan manualmente; Local Registry regula su retención.

## Instalación y soporte

La plantilla sólo requiere el puerto del panel y una ruta persistente. La
topología, las IP flotantes, las cuentas y las claves API se configuran en el portal.

Una aplicación se instala como un único contenedor. Las plantillas públicas
no contienen datos de nuestra instalación. Una plantilla descarga una imagen;
no la construye. El canal se actualiza sin cambiar la URL de la plantilla.

Soporte exclusivamente en [Unraides en Discord](https://discord.gg/8MAT6ZGJTW).
El código propio usa Apache-2.0; los componentes de terceros conservan sus
licencias y los avisos incluidos en la distribución.
