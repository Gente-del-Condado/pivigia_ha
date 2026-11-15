# Sensores y automatizaciones

La integración consulta el estado de un servicio PiVigia activo. No recibe correo ni ejecuta el detector. Puedes usarla con el complemento o con PiVigia en otro servidor.

## Instalación de la integración pública

1. Descarga el repositorio público [pivigia_ha](https://github.com/Gente-del-Condado/pivigia-ha). La URL conserva su redirección al renombrarlo.
2. Copia **solo** `custom_components/pivigia/` a `config/custom_components/pivigia/` en Home Assistant, conservando su contenido.
3. Reinicia Home Assistant.
4. Abre **Ajustes → Dispositivos y servicios → Añadir integración → PiVigia**.
5. Introduce la URL directa del servicio y su token. Ejemplo ficticio: `http://192.0.2.10:8099`.

No uses la URL de Ingress ni una dirección que redirija a un portal de acceso. El cliente no sigue redirecciones. Si cambian URL o token, utiliza las opciones de reconfiguración o reautenticación de la integración.

El principal de PiVigia permanece privado. La distribución individual de la
integración es pública y contiene custom_components/pivigia/, hacs.json y esta
guía. Puedes añadir su URL de GitHub como repositorio personalizado de tipo
Integración en HACS. Esto no significa que forme parte de su catálogo oficial.
Las aplicaciones se publican por separado en Mis_app_ha y el catálogo de
componentes para Private Git Manager está en Mis_componente_ha.

## Entidades disponibles

Se consulta el servicio cada 30 segundos. Los identificadores únicos se mantienen al cambiar de idioma. Los nombres visibles se traducen con Home Assistant y pueden personalizarse.

| Grupo | Entidades | Interpretación |
| --- | --- | --- |
| Correo | Enviados, en cola, filtrados, fallidos | Recuentos del historial retenido; en cola suma pendientes y procesamiento. |
| Diagnóstico | Versión del servidor, modelo activo | Información del servicio consultado. |
| Estado | Modelo preparado, procesamiento activo | Indicadores de disponibilidad. |
| Detección reciente | Persona, coche, animal, movimiento | Encendido si existe una observación en la ventana de 120 segundos. |
| Última detección | Persona, coche, animal, movimiento | Fecha de la observación más reciente conocida. |

No son sensores de presencia continua. El sondeo puede introducir retraso y el estado puede permanecer activo hasta terminar la ventana. Un reinicio o fallo de conexión puede dejar entidades no disponibles.

## Ejemplo de automatización

Sustituye el identificador por el de tu entidad real, que depende del nombre y de tu instalación. La acción crea una notificación persistente en Home Assistant:

```yaml
alias: PiVigia — detección reciente de persona
triggers:
  - trigger: state
    entity_id: binary_sensor.sustituye_por_tu_sensor_de_persona
    from: "off"
    to: "on"
actions:
  - action: persistent_notification.create
    data:
      title: "PiVigia"
      message: "Se ha registrado una detección reciente de persona. Revisa Actividad."
mode: single
```

Usar `from: "off"` evita dispararla simplemente al pasar de no disponible a encendido. Mientras la detección siga encendida no habrá otro cambio de estado; no equivale a una notificación por cada imagen.

## Actualizar

Copia la nueva carpeta de integración sobre la existente y reinicia Home Assistant. Conserva la configuración y no cambies los identificadores únicos del código. La actualización del complemento no reemplaza automáticamente esta carpeta.

El ejemplo sigue los [disparadores de estado de Home Assistant](https://www.home-assistant.io/docs/automation/trigger/) y la acción oficial de [notificación persistente](https://www.home-assistant.io/integrations/persistent_notification/). Los requisitos de distribución se describen en [HACS](https://www.hacs.xyz/docs/publish/start/).
