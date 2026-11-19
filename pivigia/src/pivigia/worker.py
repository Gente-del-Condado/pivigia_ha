"""Procesa la cola y persiste entregas parciales para reintentar destinos pendientes."""
import json
import logging
import re
import smtplib
import ssl
import threading
import time
from contextlib import ExitStack
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate, make_msgid

from .detector import Detector
from .notifications import alert_text, prepare_images, set_email_content
from .telegram import TelegramClient, TelegramError
from .i18n import tr, service_language, use_language

log = logging.getLogger(__name__)
MAX_MIME_PARTS = 128


class MessageLimitError(ValueError):
    """La estructura MIME excede el presupuesto, aunque quepa en el límite SMTP."""


def parse_message(raw):
    """Cuenta también contenedores y correos anidados antes de crear cada nodo."""
    parts = 0

    def factory(*, policy):
        nonlocal parts
        parts += 1
        if parts > MAX_MIME_PARTS:
            raise MessageLimitError()
        return EmailMessage(policy=policy)

    return BytesParser(policy=policy.default.clone(message_factory=factory)).parsebytes(raw)


def tls_error_description(error):
    """Traduce códigos X.509 de OpenSSL sin copiar nombres ni mensajes del proveedor."""
    if isinstance(error, ssl.SSLCertVerificationError):
        code = getattr(error, "verify_code", None)
        # X509_V_ERR_HOSTNAME_MISMATCH e IP_ADDRESS_MISMATCH: nunca aceptar otro nombre.
        if code in {62, 64}:
            return tr("El certificado TLS no corresponde al nombre del servidor configurado. Usa el nombre SMTP indicado por tu proveedor o corrige el certificado del servidor.")
        if code == 9:
            return tr("El certificado TLS todavía no es válido. Revisa la fecha y hora del equipo y la vigencia del certificado del servidor.")
        if code == 10:
            return tr("El certificado TLS ha caducado. Revisa la fecha y hora del equipo y renueva el certificado del servidor.")
        if code in {18, 19}:
            return tr("La cadena TLS contiene un certificado autofirmado que no es de confianza. Configura un certificado emitido por una autoridad de confianza en el servidor.")
        if code in {2, 20, 21}:
            return tr("No se pudo verificar la cadena del certificado TLS. Revisa los certificados intermedios del servidor y las autoridades de confianza del contenedor.")
        return tr("No se pudo verificar el certificado TLS. Revisa su nombre, vigencia y cadena de confianza; no desactives la verificación.")
    return tr("No se pudo establecer la conexión TLS. Revisa el puerto y la seguridad: normalmente SSL/TLS directo usa 465 y STARTTLS usa 587.")


def delivery_description(error):
    """Solo los errores construidos por PiVigia pueden aportar texto al historial."""
    if isinstance(error, (DeliveryError, TelegramError)):
        return str(error)
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return tr("El servidor SMTP rechazó las credenciales.")
    if isinstance(error, ssl.SSLError):
        return tls_error_description(error)
    if isinstance(error, (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused)):
        return smtp_refusal_description(error)
    return tr("No se pudo completar la entrega. Revisa la configuración y la conexión.")


def _smtp_sender_refusal(code, response):
    """Reconoce respuestas de Postfix sin copiar su contenido al diagnóstico."""
    if not isinstance(code, int) or not 400 <= code <= 599:
        return None
    if not isinstance(response, (bytes, str)) or len(response) > 4096:
        return None
    if isinstance(response, bytes):
        response = response.decode("ascii", errors="replace")
    # smtpd_delay_reject puede aplazar el rechazo del remitente hasta RCPT TO.
    # Ni 553 ni 5.7.1 bastan: también se usan para destinatarios y permisos de relay.
    match = re.fullmatch(
        r"[45]\.\d{1,3}\.\d{1,3} (?:<[^>\r\n]*>: )?"
        r"Sender address rejected: (?P<reason>[^\r\n]+)", response, re.IGNORECASE,
    )
    if not match:
        return None
    reason = match["reason"].lower()
    if reason.startswith("not owned by user ") or reason == "not logged in":
        return "unauthorized"
    return "sender"


def smtp_refusal_description(error, *, test=False):
    """Comparte mensajes propios entre prueba e historial, sin exponer datos SMTP."""
    if isinstance(error, smtplib.SMTPSenderRefused):
        reasons = [_smtp_sender_refusal(error.smtp_code, error.smtp_error) or "sender"]
    else:
        reasons = [_smtp_sender_refusal(code, response) for code, response in error.recipients.values()]
    # Con varios destinos, solo atribuir todo el fallo al remitente si cada respuesta lo confirma.
    if reasons and all(reason == "unauthorized" for reason in reasons):
        return tr("El servidor SMTP no autoriza el remitente. Usa la dirección de la cuenta con la que te autenticas o un alias autorizado para ella.")
    if reasons and all(reason is not None for reason in reasons):
        return tr("El servidor SMTP rechazó el remitente. Revisa su dirección y los permisos de envío de la cuenta SMTP.")
    if test:
        return tr("El servidor rechazó el destinatario de prueba.")
    return tr("El servidor SMTP rechazó el destinatario.")


class ShutdownRequested(Exception):
    pass


class DeliveryError(RuntimeError):
    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = retry_after


class Worker:
    def __init__(self, store, detector=None):
        self.store = store
        self.detector = detector or Detector(store.path / "models")
        self.stop_event = threading.Event()
        self.thread = None
        self.telegram_last_sent = {}

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name="pivigia-worker")
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=35)

    def run(self):
        ticks = 0
        while not self.stop_event.is_set():
            try:
                job = self.store.claim()
                if job:
                    self.process(job)
                else:
                    self.stop_event.wait(1)
                ticks += 1
                if ticks % 60 == 0:
                    self.store.cleanup(self.store.settings().retention_days)
            except Exception as error:
                # Los errores de dependencias pueden incluir credenciales o valores de ajustes.
                log.error("%s: %s", tr("Error del trabajador"), type(error).__name__)
                self.stop_event.wait(2)

    def process(self, job):
        # El contexto de idioma se libera incluso cuando falla la carga de ajustes.
        with ExitStack() as scope:
            self._process(job, scope)

    def _process(self, job, scope):
        settings = None
        try:
            settings = self.store.settings()
            scope.enter_context(use_language(service_language(settings.language)))
            mailbox = next((b for b in settings.mailboxes if b.address == job["mailbox"] and b.enabled), None)
            if mailbox is None:
                self.store.update(
                    job["id"], status="discarded", error=tr("Buzón desactivado o eliminado"), raw=None
                )
                return
            message = parse_message(job["raw"])
            if message.get("X-PiVigia"):
                self.store.update(job["id"], status="discarded", error=tr("Bucle de reenvío evitado"), raw=None)
                return
            result = json.loads(job["result"])
            if result.get("schema") != 2:
                detections, skipped, valid_images = [], [], []
                count = 0
                for part in message.walk():
                    if part.get_content_maintype() != "image":
                        continue
                    count += 1
                    if count > settings.max_images:
                        skipped.append(tr("Se alcanzó el límite de imágenes por correo"))
                        break
                    found, reason = self.detector.detect(
                        part.get_payload(decode=True) or b"", settings, mailbox.confidence
                    )
                    detections.extend({**d, "image": count} for d in found)
                    if not reason:
                        valid_images.append(count)
                    if reason:
                        skipped.append(reason)
                result = {
                    "analyzed": True,
                    "schema": 2,
                    "valid_images": valid_images,
                    "images": min(count, settings.max_images),
                    "detections": detections,
                    "skipped": skipped,
                }
                self.store.update(job["id"], result=json.dumps(result))
            matches = [d for d in result["detections"] if d["category"] in mailbox.categories]
            if not mailbox.should_notify(result["detections"], result["valid_images"], result["skipped"]):
                self.store.update(job["id"], status="filtered", raw=None)
                return
            chats = mailbox.telegram_chat_ids if settings.telegram_enabled else []
            if not mailbox.destinations and not chats:
                self.store.update(
                    job["id"], status="filtered", error=tr("Sin destinos de correo o Telegram"), raw=None
                )
                return
            images = prepare_images(message, result, mailbox)
            delivered = json.loads(job["delivered"])
            failures, retry_after = [], 0

            def deliver(key, callback, channel):
                nonlocal retry_after
                if key in delivered:
                    return
                if self.stop_event.is_set():
                    raise ShutdownRequested()
                try:
                    callback()
                except ShutdownRequested:
                    raise
                except Exception as error:
                    failures.append(f"{channel}: {delivery_description(error)}")
                    retry_after = max(retry_after, getattr(error, "retry_after", 0))
                    return
                delivered.append(key)
                self.store.update(job["id"], delivered=json.dumps(delivered))

            for destination in mailbox.destinations:
                deliver(
                    destination,
                    lambda: self.forward(settings, destination, message, job, result, images),
                    tr("Correo {destination}", destination=destination),
                )
            if chats:
                client = TelegramClient(settings.telegram_bot_token)
                bot_id = settings.telegram_bot_token.split(":")[0]
                for chat in chats:
                    for asset in images or [None]:
                        index = asset["index"] if asset else "text"
                        key = f"telegram:{bot_id}:{chat}:{index}"
                        caption = alert_text(
                            job,
                            message,
                            asset["detections"] if asset else matches,
                            asset["index"] if asset else None,
                            inverse=mailbox.invert_detection,
                        )
                        if not asset:
                            caption += tr("\nNo hay imágenes aptas para adjuntar.")
                        deliver(
                            key,
                            lambda: self.send_telegram(client, bot_id, chat, asset, caption),
                            tr("Telegram {chat}", chat=chat),
                        )
            if failures:
                raise DeliveryError("; ".join(failures), retry_after)
            self.store.update(job["id"], status="sent", raw=None, error="")
        except ShutdownRequested:
            self.store.update(job["id"], status="queued", next_try=0)
        except MessageLimitError:
            # No reintentar automáticamente una estructura que seguirá excediendo el límite.
            self.store.update(job["id"], status="failed", attempts=job["attempts"] + 1,
                              error=tr("Correo rechazado: demasiadas partes MIME."))
        except Exception as error:
            attempts = job["attempts"] + 1
            # No basta con sustituir secretos literales: podrían llegar codificados o escapados.
            description = (str(error) if isinstance(error, DeliveryError) else
                           tr("No se pudo procesar el correo. Revisa la configuración y los modelos."))
            self.store.update(
                job["id"],
                attempts=attempts,
                status="failed" if attempts >= 5 else "queued",
                next_try=time.time() + max(min(3600, 30 * 2**attempts), getattr(error, "retry_after", 0)),
                error=description[:400],
            )
            log.warning(tr("Trabajo %s pendiente/fallido: %s"), job["id"], type(error).__name__)

    def send_telegram(self, client, bot_id, chat, asset, caption):
        destination = (bot_id, chat)
        interval = 3.1 if chat.startswith("-") else 1.05
        delay = max(0, self.telegram_last_sent.get(destination, 0) + interval - time.monotonic())
        if self.stop_event.wait(delay):
            raise ShutdownRequested()
        if asset:
            client.send_photo(chat, asset["content"], caption)
        else:
            client.send_message(chat, caption)
        self.telegram_last_sent[destination] = time.monotonic()

    @staticmethod
    def forward(settings, destination, original, job, result, images=None):
        with use_language(service_language(settings.language)):
            Worker._forward(settings, destination, original, job, result, images)

    @staticmethod
    def _forward(settings, destination, original, job, result, images=None):
        if not settings.smtp_host or not settings.smtp_from:
            raise DeliveryError(tr("Configura el servidor SMTP de salida y el remitente"))
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = destination
        subject = str(original.get("Subject", tr("(sin asunto)"))).replace("\r", "").replace("\n", "")
        message["Subject"] = "[PiVigia] " + subject[:200]
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(idstring=f"pivigia-{job['id']}")
        message["X-PiVigia"] = "1"
        mailbox = next(b for b in settings.mailboxes if b.address == job["mailbox"])
        if images is None:
            images = prepare_images(original, result, mailbox)
        set_email_content(message, job, original, result, mailbox, images)
        Worker.send_email(settings, destination, message)

    @staticmethod
    def send_email(settings, destination, message):
        if not settings.smtp_host or not settings.smtp_from:
            raise DeliveryError(tr("Configura el servidor SMTP de salida y el remitente"))
        context = ssl.create_default_context()
        if settings.smtp_security == "ssl":
            smtp = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=context)
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        with smtp:
            if settings.smtp_security == "starttls":
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message, from_addr=settings.smtp_from, to_addrs=[destination])
