# AppArmor de PiVigia

El complemento incluye su perfil en `addons/pivigia/apparmor.txt`, junto al
manifiesto. Supervisor lo carga en **enforce**, con la protección activada.
No cambia los puertos, opciones, modelos ni datos de las instalaciones existentes.

## Qué permite

- Python 3.12 y las bibliotecas de OpenCV, NumPy y Pillow; programas de la aplicación en solo lectura.
- SMTP/STARTTLS, RTSP, Ingress, DNS y conexiones a los proveedores de avisos y modelos.
- Escritura en `/data` y temporales: SQLite/WAL, cola, fotos, ajustes y modelos descargables.
- Lectura de los certificados opcionales de `/ssl`, sin modificarlos.

No permite ejecutar un shell, instalar programas o escribir sobre el código.
El perfil no sustituye la autenticación, los límites SMTP ni las reglas de red.
Una denegación durante un uso legítimo debe investigarse; no se resuelve
desactivando AppArmor o la protección.

## Repetir el ensayo

Utiliza un complemento independiente `pivigia_apparmor_lab`, puertos externos
desactivados y datos ficticios. Conserva las reglas del perfil y cambia solo su
nombre al slug del laboratorio. Marca su `/data/.apparmor-lab` con
`disposable-lab`. No reutilices SQLite, fotos ni credenciales de otra instalación.

Ejecuta `python scripts/check_apparmor.py --confirm-disposable-lab --download-model`
con Python dentro del contenedor protegido. Comprueba el perfil del proceso y
ejercita SQLite WAL, MobileNet real, descarga verificada y activación de YOLOX-S,
anotación JPEG, DNS/TLS y operaciones denegadas. El ensayo usa su propia carpeta
temporal; no abre la SQLite del servidor en funcionamiento.

Desde Supervisor verifica además Ingress/roles, SMTP autenticado con STARTTLS,
cola y avisos hacia receptores de prueba, RTSP sintético y conservación al
reiniciar. Repite en HAOS amd64 y aarch64. Las cámaras y los destinatarios de
producción no se utilizan. Consulta `docs/VERIFICACION.md` para resultados reales.

La puntuación se comprueba **instalada**, no solo en la tienda:
`ha apps info SLUG --raw-json` debe mostrar `apparmor: profile`, `protected: true`
y el proceso debe indicar `enforce`. Según la [fórmula de Supervisor](https://contributors.home-assistant.io/apps/reference/security-rating/),
esta configuración con Ingress puede alcanzar 8/8. El número no acredita por sí
solo que hayan pasado las pruebas funcionales.

## ABI de la política

Se declara `abi <abi/3.0>,` explícitamente. En HAOS 18.4 con parser 3.1.7, omitirlo puede dejar sin mediar las reglas de red aunque el perfil figure en enforce. Las pruebas incluyen permisos efectivos, no solo la puntuación. No retires esa declaración ni desactives la protección para evitar una denegación.

## Resultado de 0.1.9

Validado el 18 de noviembre de 2026 en HAOS 18.4, amd64 y aarch64: perfil
en enforce, protección activada, 8/8 instalada y 201 pruebas correctas en cada
arquitectura. La aceptación real incluye SMTP STARTTLS, análisis y reenvío,
RTSP sintético y persistencia al reiniciar; las denegaciones se comprueban sobre
el proceso protegido. Los resultados y límites están en
[Verificación](https://gentedelcondado.es/forgejo/wolfbelmi88/pivigia/src/branch/main/docs/VERIFICACION.md).

## Ejecutar el ayudante desde el clon

Sustituye `haos-lab` por el acceso SSH de tu laboratorio y prepara primero la
instalación desechable descrita arriba. El código se envía por stdin a Python;
no necesita permiso de ejecución sobre archivos del contenedor:

```sh
ssh root@haos-lab \
  'docker exec -i app_local_pivigia_apparmor_lab python - --confirm-disposable-lab --download-model' \
  < scripts/check_apparmor.py
```
