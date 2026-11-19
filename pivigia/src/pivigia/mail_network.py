"""Transporte saliente acotado: DNS público fijado, TLS verificado y sin redirecciones."""

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from urllib.parse import urlencode, urlsplit

from .i18n import tr
from .mail_accounts import https_url


class MailAccountError(ValueError):
    """Solo mensajes propios, nunca respuestas nativas del proveedor."""


class MailAccountBusy(MailAccountError):
    """El panel puede reintentar sin invalidar una autorización todavía pendiente."""


def public_socket(host, port, timeout=10):
    """Resuelve una vez y conecta a esas IP: no permite DNS rebinding hacia la red interna."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or len(addresses) > 32:
        raise MailAccountError(tr("No se pudo resolver el servidor de la cuenta externa."))
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        # Las transiciones IPv6 pueden encapsular una IPv4 interna aunque el prefijo parezca público.
        transition = isinstance(ip, ipaddress.IPv6Address) and (
            ip.sixtofour is not None or ip.teredo is not None or ip in ipaddress.ip_network("64:ff9b::/96")
        )
        if not ip.is_global or ip.is_multicast or ip.is_reserved or transition:
            raise MailAccountError(
                tr(
                    "El servidor externo debe resolver únicamente a direcciones públicas. No se permiten redes internas ni direcciones locales."
                )
            )
    deadline = time.monotonic() + timeout
    for family, kind, proto, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection = socket.socket(family, kind, proto)
        try:
            connection.settimeout(remaining)
            connection.connect(address)
            return connection
        except OSError:
            connection.close()
    raise MailAccountError(tr("No se pudo conectar con el servidor de la cuenta externa."))


def tls_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def oauth_post(endpoint, fields):
    """POST OAuth sin proxies de entorno, cookies, redirecciones ni trazas con secretos."""
    https_url(endpoint)
    target = urlsplit(endpoint)
    connection = http.client.HTTPSConnection(target.hostname, 443, timeout=10, context=tls_context())
    connection._create_connection = lambda address, timeout, source_address=None: public_socket(
        *address, timeout=timeout
    )
    active_socket = []

    def interrupt():
        # El timeout de socket es por lectura; cortar también a un servidor que gotee bytes.
        sock = connection.sock or (active_socket[0] if active_socket else None)
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    timer = threading.Timer(20, interrupt)
    timer.daemon = True
    timer.start()
    try:
        connection.request(
            "POST",
            target.path or "/",
            body=urlencode(fields).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        active_socket.append(connection.sock)
        response = connection.getresponse()
        if response.status not in {200, 400}:
            # invalid_grant, descripciones y URLs de ayuda del proveedor no salen del transporte.
            raise MailAccountError(
                tr(
                    "El proveedor rechazó la autorización OAuth2. Revisa el cliente, los permisos y la URL de retorno; vuelve a conectar la cuenta."
                )
            )
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > 65_536):
            raise ValueError()
        raw = response.read(65_537)
        if len(raw) > 65_536:
            raise ValueError()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError()
        if response.status == 400:
            error = payload.get("error")
            if error not in {"authorization_pending", "slow_down", "access_denied", "expired_token"}:
                raise MailAccountError(
                    tr(
                        "El proveedor rechazó la autorización OAuth2. Revisa el cliente, los permisos y la URL de retorno; vuelve a conectar la cuenta."
                    )
                )
            return {"error": error}
        return payload
    except MailAccountError:
        raise
    except Exception:
        raise MailAccountError(
            tr(
                "No se pudo completar la conexión OAuth2 segura. Revisa el proveedor, la conexión y su certificado."
            )
        ) from None
    finally:
        timer.cancel()
        connection.close()


def token_request(endpoint, fields, *, pending=False):
    payload = oauth_post(endpoint, fields)
    if "error" in payload:
        if pending and payload["error"] in {"authorization_pending", "slow_down"}:
            return payload
        raise MailAccountError(
            tr(
                "El proveedor rechazó la autorización OAuth2. Revisa el cliente, los permisos y la URL de retorno; vuelve a conectar la cuenta."
            )
        )
    try:
        token = payload.get("access_token")
        refresh = payload.get("refresh_token", "")
        expires = int(payload.get("expires_in", 3600))
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 16_384
            or not isinstance(refresh, str)
            or len(refresh) > 16_384
            or any(ord(c) < 32 or ord(c) == 127 for c in token + refresh)
            or payload.get("token_type", "").lower() != "bearer"
            or not 30 <= expires <= 604_800
        ):
            raise ValueError()
        return {"access_token": token, "refresh_token": refresh, "expires_at": time.time() + expires}
    except Exception:
        raise MailAccountError(
            tr("El proveedor devolvió una autorización no válida. Inicia la conexión de nuevo.")
        ) from None
