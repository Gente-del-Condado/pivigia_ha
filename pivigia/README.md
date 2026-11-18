# PiVigia para Home Assistant

Servicio de análisis local de fotos recibidas por SMTP, con avisos por correo y Telegram. Incluye modelos descargables, pruebas sin avisos y cámaras RTSP opcionales.

Añade `https://github.com/Gente-del-Condado/Mis_app_ha` a los repositorios de la tienda y selecciona **PiVigia**. Configura un `admin_token` de al menos 16 caracteres, guarda e inicia.

Si ya lo instalaste desde Forgejo, otro repositorio o una carpeta local, conserva esa instancia y sus datos: añadir Mis_app_ha crea otra identidad de complemento y no migra la instalación anterior automáticamente.

**Certificado y clave STARTTLS de entrada son opcionales.** Omite ambos si no los necesitas. La autenticación SMTP sin TLS requiere habilitarla expresamente para una red local de confianza.

Esta carpeta se publica automáticamente desde el proyecto PiVigia. Incluye todo lo necesario para construir el complemento en AMD64 o ARM64; la integración de sensores se instala por separado. No edites la copia de Mis_app_ha: la siguiente sincronización la reemplaza.

Consulta [la documentación completa del complemento](DOCS.md): opciones, ejemplos YAML, puertos, acceso, primer aviso, sensores y actualización. Esa página se genera desde `docs/HOME_ASSISTANT.md`; edita allí el contenido.

Los datos privados viven en `/data` del complemento. Haz una copia antes de actualizar la instancia existente. La versión se declara en `config.yaml` y el historial está en [Cambios](CHANGELOG.md).

## Origen y distribución

El principal privado se mantiene primero en
[Forgejo](https://gentedelcondado.es/forgejo/wolfbelmi88/pivigia) y se replica a
[GitHub](https://github.com/Gente-del-Condado/pivigia). Actions supera CI y copia
este complemento a Mis_app_ha. No se publica de vuelta a Forgejo. La integración
se instala por separado desde
[pivigia_ha](https://github.com/Gente-del-Condado/pivigia_ha).

## AppArmor

Desde 0.1.9 se incluye un [perfil propio](APPARMOR.md), validado en amd64 y
aarch64. Mantiene SMTP/STARTTLS, RTSP, inferencia y descarga de modelos, panel
y avisos. El proceso puede guardar sus datos en `/data`, pero no ejecutar un
shell ni modificar el programa. Conserva la protección de Home Assistant activada.
