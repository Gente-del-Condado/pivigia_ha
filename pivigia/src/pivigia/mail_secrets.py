"""Cifrado autenticado de credenciales externas; la clave pertenece al directorio de datos."""

import json
import os
import stat

from cryptography.fernet import Fernet, InvalidToken

from .i18n import tr


class MailSecretError(ValueError):
    """Error seguro que nunca incluye la clave ni el texto cifrado."""


class MailSecrets:
    def __init__(self, path, *, required=False):
        path = path / "mail-secrets.key"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if required:
                raise MailSecretError(
                    tr(
                        "Falta la clave de las cuentas externas. Restaura mail-secrets.key desde la misma copia de seguridad."
                    )
                ) from None
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(Fernet.generate_key())
                file.flush()
                os.fsync(file.fileno())
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise MailSecretError(tr("La clave de las cuentas externas no es un archivo privado válido."))
            os.fchmod(file.fileno(), 0o600)
            key = file.read(45)
        try:
            self.cipher = Fernet(key)
        except (ValueError, TypeError):
            raise MailSecretError(
                tr("La clave de las cuentas externas no es válida. Restaura la copia de seguridad completa.")
            ) from None

    def encrypt(self, value, purpose):
        content = json.dumps({"purpose": purpose, "value": value}).encode()
        return "enc:v1:" + self.cipher.encrypt(content).decode("ascii")

    def decrypt(self, value, purpose):
        try:
            if not isinstance(value, str) or not value.startswith("enc:v1:"):
                raise ValueError()
            content = json.loads(self.cipher.decrypt(value[7:].encode("ascii")))
            if content["purpose"] != purpose:
                raise ValueError()
            return content["value"]
        except (InvalidToken, UnicodeError, ValueError, TypeError, KeyError):
            raise MailSecretError(
                tr(
                    "No se pudieron abrir las credenciales externas. Restaura la clave y la base de datos de la misma copia."
                )
            ) from None

    def settings(self, data, *, decrypt=False):
        """Opera sobre una copia JSON; nunca cifra hashes locales ni reescribe otros ajustes."""
        for box in data.get("mailboxes", []):
            external = box.get("external")
            if external:
                for field in ("password", "client_secret"):
                    value = external.get(field, "")
                    if value:
                        purpose = "setting:" + box["address"] + ":" + field
                        external[field] = (
                            self.decrypt(value, purpose) if decrypt else self.encrypt(value, purpose)
                        )
        return data
