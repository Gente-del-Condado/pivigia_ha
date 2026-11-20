"""Salida compartida por alertas y pruebas; OAuth2 utiliza el bloqueo de la cuenta IMAP."""

import smtplib
import socket
import threading
import time
from contextlib import contextmanager

from .i18n import tr
from .mail_network import MailAccountError, public_socket, tls_context


class PublicSMTP(smtplib.SMTP):
    """Fija la IP pública validada, mantiene SNI y acota las respuestas del proveedor."""

    def __init__(self, account):
        self.account = account
        self.context = tls_context()
        self.transport = None
        self.reply_bytes = 0
        self.deadline = time.monotonic() + 45
        super().__init__(timeout=10)
        self._host = account.smtp_host

    def _get_socket(self, host, port, timeout):
        self.transport = public_socket(host, port, timeout=timeout)
        if time.monotonic() >= self.deadline:
            raise TimeoutError()
        if self.account.smtp_security == "ssl":
            self.transport = self.context.wrap_socket(self.transport, server_hostname=host)
        return self.transport

    def getreply(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError()
        # smtplib limita cada línea pero no el total de una respuesta multilínea.
        if self.file is None:
            self.file = self.sock.makefile("rb")
        response = []
        while True:
            line = self.file.readline(8193)
            self.reply_bytes += len(line)
            if len(line) > 8192 or self.reply_bytes > 65_536:
                raise MailAccountError(tr("La respuesta SMTP supera los límites de seguridad."))
            if not line:
                raise smtplib.SMTPServerDisconnected()
            if len(line) < 4 or not line[:3].isdigit() or line[3:4] not in {b"-", b" "}:
                raise smtplib.SMTPResponseException(-1, b"")
            response.append(line[4:].strip(b" \t\r\n"))
            if line[3:4] != b"-":
                return int(line[:3]), b"\n".join(response)

    def interrupt(self):
        # Corta también un servidor que entrega bytes lentamente para eludir el timeout.
        for sock in (self.sock, self.transport):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        super().close()
        if self.transport is not None:
            self.transport.close()


@contextmanager
def external_smtp(account):
    smtp = PublicSMTP(account)
    timer = threading.Timer(45, smtp.interrupt)
    timer.daemon = True
    timer.start()
    try:
        code, _ = smtp.connect(account.smtp_host, account.smtp_port)
        if code != 220:
            raise smtplib.SMTPConnectError(code, b"")
        if account.smtp_security == "starttls":
            smtp.starttls(context=smtp.context)
        smtp.ehlo_or_helo_if_needed()
        yield smtp
    finally:
        timer.cancel()
        # Una caída durante QUIT no debe transformar un DATA ya aceptado en fallo.
        smtp.close()


class MailSender:
    def __init__(self, store, reader):
        self.store = store
        self.reader = reader

    def unchanged(self, address, snapshot):
        if self.reader.account(address).external.signature() != snapshot.signature():
            raise MailAccountError(tr("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada."))

    @staticmethod
    def identity(settings, account=None):
        """Resuelve únicamente ajustes guardados; nunca acepta servidores desde la prueba."""
        selected = settings.smtp_account if account is None else account
        if not selected:
            if not settings.smtp_host or not settings.smtp_from:
                raise MailAccountError(tr("Guarda primero el servidor SMTP de salida y el remitente en Configuración."))
            return {"account": "", "sender": settings.smtp_from, "host": settings.smtp_host,
                    "port": settings.smtp_port, "security": settings.smtp_security, "auth": "password"}
        box = next((b for b in settings.mailboxes if b.address == selected and b.source == "imap"), None)
        if not box or not box.external.smtp_enabled:
            raise MailAccountError(tr("La cuenta elegida para las alertas no existe o no tiene habilitado el envío."))
        a = box.external
        return {"account": box.address, "sender": a.smtp_from, "host": a.smtp_host,
                "port": a.smtp_port, "security": a.smtp_security, "auth": a.auth}

    def send(self, settings, destination, message, account=None):
        identity = self.identity(settings, account)
        selected = identity["account"]
        if not selected:
            from .worker import Worker
            Worker.send_email(settings, destination, message)
            return identity
        with self.reader.operation(selected):
            snapshot = next(b.external for b in settings.mailboxes if b.address == selected)
            current = self.reader.account(selected).external
            if current.signature() != snapshot.signature():
                raise MailAccountError(tr("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada."))
            # Acceso y renovación bajo el mismo bloqueo que IMAP y desconectar OAuth2.
            access = self.reader.oauth.access_token(selected, current) if current.auth == "oauth2" else None
            if access is None and not current.password:
                raise MailAccountError(tr("Guarda la contraseña de la cuenta externa antes de enviar."))
            try:
                with external_smtp(current) as smtp:
                    self.unchanged(selected, current)
                    if access is not None:
                        if "XOAUTH2" not in smtp.esmtp_features.get("auth", "").upper().split():
                            raise MailAccountError(tr("El servidor SMTP no ofrece XOAUTH2. Revisa el proveedor y los permisos de envío."))
                        data = "user=" + current.username + "\x01auth=Bearer " + access + "\x01\x01"
                        # smtplib envía la respuesta inicial una vez; un desafío de error
                        # recibe una cadena vacía, nunca otro token ni una contraseña.
                        smtp.auth("XOAUTH2", lambda challenge=None: data if challenge is None else "")
                    else:
                        smtp.login(current.username, current.password)
                    self.unchanged(selected, current)
                    smtp.send_message(message, from_addr=identity["sender"], to_addrs=[destination])
            except smtplib.SMTPAuthenticationError:
                if access is not None:
                    raise MailAccountError(tr("El servidor SMTP rechazó OAuth2. Vuelve a conectar la cuenta y comprueba que permite enviar correo y tiene los permisos SMTP necesarios.")) from None
                raise
        return identity
