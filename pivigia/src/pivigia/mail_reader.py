"""Importación IMAP de solo lectura a la cola existente, con límites por cuenta y transacción."""

import imaplib
import logging
import re
import ssl
import threading
import time
from contextlib import contextmanager

from .i18n import N_, service_language, tr, use_language
from .mail_network import MailAccountBusy, MailAccountError, public_socket, tls_context
from .mail_oauth import MailOAuth
from .smtp import MAX_MESSAGE
from .worker import tls_error_description

log = logging.getLogger(__name__)
MAX_BATCH = 20
UID_WINDOW = 100
NETWORK_SECONDS = 45
STATUS_TEXT = {
    "disabled": N_("Cuenta desactivada."),
    "waiting": N_("Pendiente de la primera conexión."),
    "connected": N_("Conexión IMAP correcta."),
    "initialized": N_("Seguimiento iniciado. Solo se importarán los mensajes que lleguen desde ahora."),
    "full": N_("Cola llena. Los mensajes externos pendientes se conservarán para el próximo intento."),
    "changed": N_("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada."),
    "reset": N_(
        "El servidor cambió la identidad de la carpeta. Revisa el buzón y reinicia el seguimiento desde ahora."
    ),
}


class BoundedIMAP(imaplib.IMAP4_SSL):
    """Acota líneas, literales, bytes y tiempo aunque el servidor anuncie tamaños falsos."""

    def __init__(self, host, port):
        self.deadline = time.monotonic() + NETWORK_SECONDS
        self._buffer = bytearray()
        self.budget = 131_072
        self.literal_limit = 0
        self.total_budget = 32_000_000
        super().__init__(host, port, ssl_context=tls_context(), timeout=10)

    def _create_socket(self, timeout):
        sock = public_socket(self.host, self.port, timeout=timeout)
        try:
            return self.ssl_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise

    def command_budget(self, literal=0):
        self.literal_limit = literal
        self.budget = literal + 131_072

    def _chunk(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.sock.settimeout(min(10, remaining))
        chunk = self.sock.recv(4096)
        self.budget -= len(chunk)
        self.total_budget -= len(chunk)
        if self.budget < 0 or self.total_budget < 0:
            raise MailAccountError(tr("La respuesta IMAP supera los límites de seguridad."))
        return chunk

    def readline(self):
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > 65_535:
                    raise MailAccountError(tr("La respuesta IMAP supera los límites de seguridad."))
                line = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                return line
            if len(self._buffer) > 65_536:
                raise MailAccountError(tr("La respuesta IMAP supera los límites de seguridad."))
            chunk = self._chunk()
            if not chunk:
                line = bytes(self._buffer)
                self._buffer.clear()
                return line
            self._buffer.extend(chunk)

    def read(self, size):
        if size > self.literal_limit or size > MAX_MESSAGE:
            raise MailAccountError(tr("El mensaje externo supera el tamaño permitido."))
        result = bytearray(self._buffer[:size])
        del self._buffer[:size]
        while len(result) < size:
            chunk = self._chunk()
            if not chunk:
                break
            needed = size - len(result)
            result.extend(chunk[:needed])
            self._buffer.extend(chunk[needed:])
        return bytes(result)


def safe_error(error):
    if isinstance(error, MailAccountError):
        return str(error)
    if isinstance(error, ssl.SSLError):
        return tls_error_description(error)
    if isinstance(error, imaplib.IMAP4.error):
        return tr("El servidor IMAP rechazó la operación. Revisa el usuario, la autorización y la carpeta.")
    return tr("No se pudo consultar la cuenta externa. Revisa el servidor, la conexión y sus permisos.")


def require_ok(result):
    if result[0] != "OK":
        raise MailAccountError(
            tr("El servidor IMAP rechazó la operación. Revisa el usuario, la autorización y la carpeta.")
        )
    return result[1]


def response_number(client, name):
    kind, values = client.response(name)
    if kind != name or not values or len(values) != 1 or not re.fullmatch(rb"[0-9]{1,10}", values[0] or b""):
        raise MailAccountError(tr("El servidor no ofrece un seguimiento IMAP seguro de esta carpeta."))
    value = int(values[0])
    if not 1 <= value <= 4_294_967_295:
        raise MailAccountError(tr("El servidor no ofrece un seguimiento IMAP seguro de esta carpeta."))
    return value


class MailReader:
    def __init__(self, store, client_factory=BoundedIMAP):
        self.store = store
        self.oauth = MailOAuth(store)
        self.client_factory = client_factory
        self.stop_event = threading.Event()
        self.thread = None
        self.guard = threading.Lock()
        self.locks = {}
        self.states = {}
        self.due = {}

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name="pivigia-imap")
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=NETWORK_SECONDS + 15)

    @contextmanager
    def operation(self, address):
        self.account(address)
        with self.guard:
            lock = self.locks.setdefault(address, threading.Lock())
            acquired = lock.acquire(blocking=False)
        if not acquired:
            raise MailAccountBusy(tr("Esta cuenta ya tiene una operación en curso. Espera a que termine."))
        try:
            yield
        finally:
            lock.release()

    def account(self, address):
        box = next(
            (b for b in self.store.settings().mailboxes if b.address == address and b.source == "imap"), None
        )
        if not box:
            raise MailAccountError(
                tr("La cuenta externa ya no existe. Guarda los cambios y vuelve a probar.")
            )
        return box

    def _state(self, address, code, detail=""):
        with self.guard:
            self.states[address] = {"status": code, "detail": detail, "last_attempt": time.time()}

    def status(self):
        settings = self.store.settings()
        result = []
        for box in settings.mailboxes:
            if box.source != "imap":
                continue
            with self.guard:
                state = dict(
                    self.states.get(box.address, {"status": "waiting", "detail": "", "last_attempt": None})
                )
            if not box.enabled:
                state.update(status="disabled", detail="")
            position = self.store.mail_position(box.address)
            if position and position["source"] != box.external.source_key():
                position = None
            result.append(
                {
                    "address": box.address,
                    **state,
                    "detail": state["detail"] or tr(STATUS_TEXT.get(state["status"], STATUS_TEXT["waiting"])),
                    "checked": position["checked"] if position else None,
                    "imported": position["imported"] if position else 0,
                    "skipped": position["skipped"] if position else 0,
                    "authorized": bool(self.store.mail_tokens(box.address, box.external.oauth_key()))
                    if box.external.auth == "oauth2"
                    else bool(box.external.password),
                }
            )
        return result

    @contextmanager
    def connection(self, box):
        account = box.external
        client = self.client_factory(account.host, account.port)
        try:
            if account.auth == "oauth2":
                access = self.oauth.access_token(box.address, account)
                data = ("user=" + account.username + "\x01auth=Bearer " + access + "\x01\x01").encode()
                # Las respuestas de error XOAUTH2 no deben provocar el reenvío del token.
                sent = False

                def authenticate(challenge):
                    nonlocal sent
                    if sent:
                        return b""
                    sent = True
                    return data

                require_ok(client.authenticate("XOAUTH2", authenticate))
            else:
                if not account.password:
                    raise MailAccountError(tr("Guarda la contraseña de la cuenta externa antes de probar."))
                if "LOGINDISABLED" in client.capabilities:
                    raise MailAccountError(
                        tr(
                            "El servidor IMAP no permite contraseña. Configura OAuth2 si el proveedor lo admite."
                        )
                    )
                require_ok(client.login(account.username, account.password))
            # EXAMINE y BODY.PEEK no marcan como leído ni modifican el buzón.
            folder = '"' + account.folder.replace("\\", "\\\\").replace('"', '\\"') + '"'
            require_ok(client.select(folder, readonly=True))
            validity = response_number(client, "UIDVALIDITY")
            next_uid = response_number(client, "UIDNEXT")
            yield client, validity, next_uid
        finally:
            # No usar CLOSE ni EXPUNGE; shutdown cierra únicamente nuestra conexión.
            client.shutdown()

    def probe(self, address):
        with self.operation(address):
            box = self.account(address)
            try:
                with self.connection(box):
                    pass
                self._state(address, "connected")
                return {
                    "ok": True,
                    "detail": tr(
                        "Conexión IMAP correcta. La prueba no descarga mensajes ni cambia el seguimiento."
                    ),
                }
            except Exception as error:
                self._state(address, "error", safe_error(error))
                raise MailAccountError(safe_error(error)) from None

    def reset(self, address):
        with self.operation(address):
            box = self.account(address)
            if not box.enabled:
                raise MailAccountError(tr("Activa la cuenta antes de reiniciar su seguimiento."))
            with self.connection(box) as (_, validity, next_uid):
                if not self.store.begin_mail_sync(address, box.external, validity, next_uid - 1, reset=True):
                    raise MailAccountError(
                        tr(
                            "La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada."
                        )
                    )
            self._state(address, "initialized")
            return {"ok": True, "detail": tr(STATUS_TEXT["initialized"])}

    def poll(self, box):
        account = box.external
        with self.connection(box) as (client, validity, next_uid):
            position = self.store.mail_position(box.address)
            if not position or position["source"] != account.source_key():
                if self.store.begin_mail_sync(box.address, account, validity, next_uid - 1):
                    return "initialized"
                return "changed"
            if position["uidvalidity"] != validity or next_uid - 1 < position["last_uid"]:
                return "reset"
            previous = position["last_uid"]
            if previous >= next_uid - 1:
                self.store.mail_checked(box.address)
                return "connected"
            end = min(previous + UID_WINDOW, next_uid - 1)
            client.command_budget()
            rows = require_ok(client.uid("FETCH", f"{previous + 1}:{end}", "(UID RFC822.SIZE)"))
            entries = {}
            for row in rows:
                if row is None:
                    continue
                if not isinstance(row, bytes):
                    raise MailAccountError(tr("La respuesta IMAP supera los límites de seguridad."))
                uid_match = re.search(rb"\bUID ([0-9]{1,10})\b", row)
                size_match = re.search(rb"\bRFC822\.SIZE ([0-9]{1,12})\b", row)
                if not uid_match or not size_match:
                    raise MailAccountError(
                        tr("El servidor no ofrece un seguimiento IMAP seguro de esta carpeta.")
                    )
                uid, size = int(uid_match[1]), int(size_match[1])
                if not previous < uid <= end or uid in entries:
                    raise MailAccountError(
                        tr("El servidor no ofrece un seguimiento IMAP seguro de esta carpeta.")
                    )
                entries[uid] = size
            for uid, size in sorted(entries.items())[:MAX_BATCH]:
                if self.stop_event.is_set():
                    return "connected"
                raw = None
                skipped = size == 0 or size > MAX_MESSAGE
                if not skipped:
                    client.command_budget(size)
                    parts = require_ok(client.uid("FETCH", str(uid), "(UID BODY.PEEK[])"))
                    literals = [p for p in parts if isinstance(p, tuple)]
                    if len(literals) != 1:
                        # Una expulsión concurrente no avanza el cursor aquí: se resuelve en el próximo FETCH.
                        raise MailAccountError(
                            tr(
                                "El mensaje cambió durante la descarga. Se volverá a comprobar sin avanzar el seguimiento."
                            )
                        )
                    _, raw = literals[0]
                    # IMAP permite devolver UID después del literal; nunca buscarlo dentro del MIME.
                    metadata = b" ".join(p[0] if isinstance(p, tuple) else p for p in parts if p is not None)
                    returned_uids = re.findall(rb"\bUID ([0-9]{1,10})\b", metadata)
                    if len(returned_uids) != 1 or int(returned_uids[0]) != uid or len(raw) != size:
                        raise MailAccountError(
                            tr(
                                "El mensaje cambió durante la descarga. Se volverá a comprobar sin avanzar el seguimiento."
                            )
                        )
                result = self.store.import_mail(
                    box.address, account, validity, previous, uid, raw, skipped=skipped
                )
                if result != "ok":
                    return result
                previous = uid
                if skipped:
                    log.warning(tr("Cuenta externa: mensaje omitido por el límite de tamaño."))
            if len(entries) <= MAX_BATCH and previous < end:
                result = self.store.import_mail(box.address, account, validity, previous, end)
                if result != "ok":
                    return result
            return "connected"

    def run(self):
        while not self.stop_event.is_set():
            try:
                settings = self.store.settings()
                accounts = [b for b in settings.mailboxes if b.source == "imap" and b.enabled]
                with use_language(service_language(settings.language)):
                    for box in accounts:
                        if self.stop_event.is_set():
                            break
                        signature = box.external.signature()
                        last_signature, due = self.due.get(box.address, ("", 0))
                        if signature == last_signature and time.monotonic() < due:
                            continue
                        try:
                            with self.operation(box.address):
                                code = self.poll(box)
                            self._state(box.address, code)
                            if code in {"initialized", "reset", "full"}:
                                log.info(tr("Cuenta externa: %s"), tr(STATUS_TEXT[code]))
                        except Exception as error:
                            detail = safe_error(error)
                            self._state(box.address, "error", detail)
                            log.warning(tr("Cuenta externa: %s"), detail)
                        self.due[box.address] = (signature, time.monotonic() + box.external.interval)
                active = {b.address for b in settings.mailboxes if b.source == "imap"}
                with self.guard:
                    self.states = {k: v for k, v in self.states.items() if k in active}
                    self.locks = {k: v for k, v in self.locks.items() if k in active or v.locked()}
                self.due = {k: v for k, v in self.due.items() if k in active}
            except Exception:
                log.warning(
                    tr("No se pudo actualizar el lector de cuentas externas. Revisa la configuración.")
                )
            self.stop_event.wait(2)
