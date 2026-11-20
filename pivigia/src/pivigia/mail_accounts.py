"""Contratos de cuentas IMAP y proveedores; no contienen secretos de ninguna instalación."""

import hashlib
import json
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

from .i18n import tr

# Las cuentas conocidas fijan sus destinos: un token de Google/Microsoft nunca se
# puede enviar a un host elegido al editar el formulario.
PROVIDERS = {
    "gmail": {
        "host": "imap.gmail.com",
        "smtp_host": "smtp.gmail.com", "smtp_port": 465, "smtp_security": "ssl",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "scope": "https://mail.google.com/",
    },
    "outlook": {
        "host": "outlook.office365.com",
        "smtp_host": "smtp-mail.outlook.com", "smtp_port": 587, "smtp_security": "starttls",
        "authorization_endpoint": "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    },
    "gentedelcondado": {"host": "mail.gentedelcondado.es", "smtp_host": "mail.gentedelcondado.es",
                        "smtp_port": 465, "smtp_security": "ssl"},
    "custom": {},
}


def hostname(value):
    """Solo nombres DNS ASCII o IPv4; sin URL, usuario, escapes ni ámbitos IPv6."""
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError(tr("Indica un nombre de servidor válido, sin URL ni credenciales."))
    if any(
        not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")
    ):
        raise ValueError(tr("Indica un nombre de servidor válido, sin URL ni credenciales."))
    return value


def https_url(value, *, callback=False):
    """Rechaza destinos ambiguos; el retorno debe ser el callback exacto del panel."""
    if not value or len(value) > 2048 or not value.isascii() or any(ord(c) <= 32 for c in value):
        raise ValueError(tr("OAuth2 necesita direcciones HTTPS válidas, sin credenciales ni parámetros."))
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or not parsed.hostname
        or (not callback and parsed.port not in {None, 443})
        or "\\" in value
        or "%" in parsed.netloc
    ):
        raise ValueError(tr("OAuth2 necesita direcciones HTTPS válidas, sin credenciales ni parámetros."))
    hostname(parsed.hostname)
    if callback and not parsed.path.endswith("/oauth/callback"):
        raise ValueError(tr("La URL de retorno debe terminar en /oauth/callback y pertenecer a este panel."))
    return value


class ExternalMailbox(BaseModel):
    provider: Literal["gmail", "outlook", "gentedelcondado", "custom"] = "custom"
    host: str = ""
    port: int = Field(default=993, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=254)
    folder: str = Field(default="INBOX", min_length=1, max_length=200)
    interval: int = Field(default=60, ge=30, le=3600)
    auth: Literal["password", "oauth2"] = "password"
    password: str = Field(default="", max_length=1024, repr=False)
    client_id: str = Field(default="", max_length=512)
    client_secret: str = Field(default="", max_length=2048, repr=False)
    redirect_uri: str = Field(default="", max_length=2048)
    authorization_endpoint: str = Field(default="", max_length=2048)
    token_endpoint: str = Field(default="", max_length=2048)
    scope: str = Field(default="", max_length=1024)
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=465, ge=1, le=65535)
    smtp_security: Literal["ssl", "starttls"] = "ssl"
    smtp_from: str = Field(default="", max_length=254)

    @field_validator("password", "client_secret")
    @classmethod
    def safe_secret(cls, value):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(tr("Los campos del buzón no admiten caracteres de control."))
        return value

    @field_validator("username", "folder", "client_id", "scope")
    @classmethod
    def safe_text(cls, value):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(tr("Los campos del buzón no admiten caracteres de control."))
        return value.strip()

    @field_validator("folder")
    @classmethod
    def folder_ascii(cls, value):
        # IMAP utiliza modified UTF-7. Las carpetas no ASCII se pueden indicar en esa codificación.
        if not value.isascii() or not value:
            raise ValueError(tr("Usa INBOX o el nombre IMAP de la carpeta en ASCII/modified UTF-7."))
        return value

    @model_validator(mode="after")
    def validate_account(self):
        fixed = PROVIDERS[self.provider]
        if fixed.get("host"):
            self.host = fixed["host"]
            self.port = 993
        self.host = hostname(self.host)
        if fixed.get("smtp_host"):
            for key in ("smtp_host", "smtp_port", "smtp_security"):
                setattr(self, key, fixed[key])
        if self.smtp_host:
            self.smtp_host = hostname(self.smtp_host)
        if self.smtp_enabled:
            if not self.smtp_host:
                raise ValueError(tr("Indica el servidor SMTP de la cuenta de salida."))
            if not self.username.isascii():
                raise ValueError(tr("El usuario de salida SMTP debe usar caracteres ASCII."))
            # Importación local: config también define los buzones que usan este contrato.
            from .config import email_address
            self.smtp_from = email_address(self.smtp_from or self.username)
        if not self.username:
            raise ValueError(tr("Indica el usuario de la cuenta de correo."))
        if self.provider == "outlook" and self.auth != "oauth2":
            raise ValueError(tr("Outlook y Hotmail requieren OAuth2."))
        if self.provider == "outlook":
            self.client_secret = ""
            self.redirect_uri = ""
        if self.auth == "oauth2":
            if self.provider in {"gmail", "outlook"}:
                for key in ("authorization_endpoint", "token_endpoint", "scope"):
                    setattr(self, key, fixed[key])
                if self.provider == "outlook" and self.smtp_enabled:
                    self.scope += " https://outlook.office.com/SMTP.Send"
            # Se permite guardar una cuenta aún sin registrar para completar el asistente.
            for key in ("authorization_endpoint", "token_endpoint", "redirect_uri"):
                value = getattr(self, key)
                if value:
                    https_url(value, callback=key == "redirect_uri")
        return self

    def signature(self):
        """Vincula operaciones en curso a la configuración exacta, sin publicar sus valores."""
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()

    def source_key(self):
        """Cambiar contraseña o intervalo no reinicia el seguimiento de la misma carpeta."""
        data = [self.provider, self.host, self.port, self.username, self.folder]
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()

    def oauth_key(self):
        """Un cambio de identidad, destino o cliente obliga a autorizar de nuevo."""
        # Mantener las autorizaciones 0.3.0 de recepción. Habilitar el envío añade
        # explícitamente el destino SMTP a la vinculación y requiere otro consentimiento.
        data = self.model_dump(exclude={"folder", "interval", "password", "smtp_enabled",
                                        "smtp_host", "smtp_port", "smtp_security", "smtp_from"})
        if self.smtp_enabled:
            data.update(smtp_enabled=True, smtp_host=self.smtp_host, smtp_port=self.smtp_port,
                        smtp_security=self.smtp_security)
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def oauth_ready(self):
        if self.provider == "outlook":
            return bool(self.client_id)
        return all(
            (self.client_id, self.redirect_uri, self.authorization_endpoint, self.token_endpoint, self.scope)
        )


def restore_secrets(account, previous, mask):
    """Un marcador solo conserva el secreto si sigue destinado a la misma identidad."""
    for field, binding in (
        ("password", ("provider", "host", "port", "username", "auth")),
        ("client_secret", ("provider", "client_id", "authorization_endpoint", "token_endpoint")),
    ):
        if getattr(account, field) == mask:
            smtp_changed = (field == "password" and account.smtp_enabled and account.provider == "custom"
                            and previous is not None and (not previous.smtp_enabled or any(
                                getattr(account, k) != getattr(previous, k)
                                for k in ("smtp_host", "smtp_port", "smtp_security"))))
            if previous is None or smtp_changed or any(getattr(account, k) != getattr(previous, k) for k in binding):
                raise ValueError(
                    tr("Al cambiar la identidad o el servidor, introduce de nuevo sus credenciales.")
                )
            setattr(account, field, getattr(previous, field))
