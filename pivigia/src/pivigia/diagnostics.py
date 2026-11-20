"""Pruebas explícitas del administrador; las imágenes de prueba nunca encolan avisos."""


import base64
import logging
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from pydantic import BaseModel, Field, field_validator

from .config import Mailbox, email_address
from .notifications import prepare_images
from .worker import smtp_error_description
from .mail_network import MailAccountBusy
from .i18n import service_language, tr, use_language

log = logging.getLogger(__name__)


class TestEmail(BaseModel):
    model_config = {"extra": "forbid"}
    account: str | None = Field(default=None, max_length=254)
    destination: str = Field(max_length=254)
    subject: str = Field(default_factory=lambda: tr("Prueba de PiVigia"), min_length=1, max_length=160)
    text: str = Field(default_factory=lambda: tr("Este es un correo de prueba enviado desde el panel de PiVigia."),
                      min_length=1, max_length=5000)

    @field_validator("destination")
    @classmethod
    def destination_valid(cls, value):
        return email_address(value)

    @field_validator("subject")
    @classmethod
    def subject_valid(cls, value):
        if "\r" in value or "\n" in value:
            raise ValueError(tr("El asunto no admite saltos de línea"))
        return value

    @field_validator("account")
    @classmethod
    def account_valid(cls, value):
        return email_address(value) if value else value


def send_test_email(settings, test, sender):
    message = EmailMessage()
    message["To"] = test.destination
    message["Subject"] = tr("[PiVigia · prueba] ") + test.subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid()
    message["X-PiVigia"] = "1"
    message.set_content(test.text + tr("\n\nPrueba manual del correo de salida de PiVigia.\n"))
    try:
        identity = sender.identity(settings, test.account)
        message["From"] = identity["sender"]
        sender.send(settings, test.destination, message, test.account)
    except MailAccountBusy:
        raise
    except Exception as error:
        # Todos los fallos usan mensajes controlados. El registro sigue el idioma
        # del servicio y la respuesta el del panel; nunca incluir secretos o respuestas SMTP.
        with use_language(service_language(settings.language)):
            log.warning(tr("Prueba de correo fallida: %s"), smtp_error_description(error, test=True))
        raise ValueError(smtp_error_description(error, test=True)) from None
    return {"ok": True, "account": identity,
            "detail": tr("El servidor SMTP ha aceptado el correo. Comprueba la bandeja y spam; esta confirmación no garantiza su llegada a la bandeja de entrada.")}


def analyze_image(settings, detector, content, mailbox="", model=""):
    box = next((b for b in settings.mailboxes if b.address == mailbox), None)
    if mailbox and box is None:
        raise ValueError(tr("El buzón seleccionado ya no existe. Actualiza la página."))
    threshold = box.confidence if box else .5
    started = time.perf_counter()
    # Resolver y ejecutar bajo el bloqueo de inferencia para informar del modelo realmente utilizado.
    if getattr(detector, "models", None):
        with detector.lock:
            model = model or detector.models.active
            found, reason = detector.detect(content, settings, threshold, model=model)
    else:
        found, reason = detector.detect(content, settings, threshold)
    elapsed = round(time.perf_counter() - started, 3)
    found = [{**d, "image": 1} for d in found]
    categories = box.categories if box else ["person", "car", "animal"]
    matches = [d for d in found if d["category"] in categories]
    rule_matches = box.should_notify(found, not reason, bool(reason)) if box else bool(matches)
    channels = []
    if box:
        if box.destinations:
            channels.append("correo")
        if settings.telegram_enabled and box.telegram_chat_ids:
            channels.append("telegram")
    preview = None
    if not reason:
        original = EmailMessage()
        original.set_content(tr("Prueba de imagen local"))
        original.add_attachment(content, maintype="image", subtype="jpeg", filename="prueba.jpg")
        view_box = Mailbox(address="preview@pivigia.local", password="preview-only",
                           categories=categories, forward_all=True)
        assets = prepare_images(original, {"valid_images": [1], "detections": found}, view_box)
        preview = base64.b64encode(assets[0]["content"]).decode("ascii")
    return {
        "valid": reason is None, "reason": reason, "detections": found, "matches": matches,
        "confidence": threshold, "categories": categories, "preview": preview,
        "model": model or "mobilenet", "elapsed_seconds": elapsed,
        "mailbox": mailbox, "rule_matches": rule_matches,
        "would_notify": bool(box and box.enabled and rule_matches and channels), "channels": channels,
        "mailbox_enabled": box.enabled if box else None,
        "detail": tr("Solo análisis local. No se ha enviado correo ni Telegram y la imagen no se ha guardado."),
    }
