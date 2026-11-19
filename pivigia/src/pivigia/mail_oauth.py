"""OAuth2 de código con PKCE S256, estado de un uso y confirmación desde el panel autenticado."""

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from urllib.parse import urlencode

from .i18n import tr
from .mail_network import MailAccountError, oauth_post, token_request

FLOW_SECONDS = 600


class MailOAuth:
    def __init__(self, store):
        self.store = store
        self.flows = {}
        self.lock = threading.Lock()

    def _expire(self):
        now = time.monotonic()
        self.flows = {key: flow for key, flow in self.flows.items() if flow["deadline"] > now}

    def begin(self, address, account, identity):
        if account.auth != "oauth2" or not account.oauth_ready():
            if account.provider == "outlook":
                raise MailAccountError(tr("Completa el ID de cliente Microsoft antes de conectar."))
            raise MailAccountError(tr("Completa el cliente OAuth2 y su URL de retorno antes de conectar."))
        if account.provider == "outlook":
            return self.begin_device(address, account, identity)
        verifier = secrets.token_urlsafe(48)
        state, proof, cookie = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with self.lock:
            self._expire()
            # Una autorización nueva de la misma cuenta invalida la anterior.
            self.flows = {key: f for key, f in self.flows.items() if f["address"] != address}
            if len(self.flows) >= 10:
                raise MailAccountError(tr("Hay demasiadas autorizaciones pendientes. Espera unos minutos."))
            self.flows[state] = {
                "address": address,
                "account": account.model_copy(deep=True),
                "identity": identity,
                "proof": proof,
                "cookie": cookie,
                "verifier": verifier,
                "deadline": time.monotonic() + FLOW_SECONDS,
                "code": None,
                "error": False,
                "mode": "redirect",
            }
        fields = {
            "response_type": "code",
            "client_id": account.client_id,
            "redirect_uri": account.redirect_uri,
            "scope": account.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if account.provider == "gmail":
            fields.update(access_type="offline", prompt="consent")
        elif account.provider == "outlook":
            fields["prompt"] = "select_account"
        return {
            "flow": state,
            "proof": proof,
            "mode": "redirect",
            "url": account.authorization_endpoint + "?" + urlencode(fields),
        }, cookie

    def begin_device(self, address, account, identity):
        """Microsoft permite autorizar desde Ingress sin publicar un callback ni abrir puertos."""
        payload = oauth_post(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
            {"client_id": account.client_id, "scope": account.scope},
        )
        try:
            code, user_code, url = (
                payload[name] for name in ("device_code", "user_code", "verification_uri")
            )
            expires, interval = int(payload["expires_in"]), int(payload.get("interval", 5))
            if (
                not isinstance(code, str)
                or not 1 <= len(code) <= 16_384
                or not isinstance(user_code, str)
                or not re.fullmatch(r"[A-Za-z0-9-]{4,32}", user_code)
                or url != "https://microsoft.com/devicelogin"
                or not 30 <= expires <= 1800
                or not 5 <= interval <= 60
            ):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise MailAccountError(
                tr("El proveedor devolvió una autorización no válida. Inicia la conexión de nuevo.")
            ) from None
        state, proof = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self._expire()
            self.flows = {key: f for key, f in self.flows.items() if f["address"] != address}
            if len(self.flows) >= 10:
                raise MailAccountError(tr("Hay demasiadas autorizaciones pendientes. Espera unos minutos."))
            self.flows[state] = {
                "address": address,
                "account": account.model_copy(deep=True),
                "identity": identity,
                "proof": proof,
                "device_code": code,
                "mode": "device",
                "deadline": time.monotonic() + min(expires, FLOW_SECONDS),
                "interval": interval,
                "next_poll": time.monotonic() + interval,
            }
        return {"flow": state, "proof": proof, "mode": "device", "url": url, "user_code": user_code}, None

    def callback(self, state, cookie, code, denied=False):
        """El callback no guarda credenciales: exige cookie y espera confirmación administrativa."""
        with self.lock:
            self._expire()
            flow = self.flows.get(state)
            if (
                not flow
                or flow["mode"] != "redirect"
                or not cookie
                or not hmac.compare_digest(flow["cookie"], cookie)
                or flow["code"] is not None
                or flow["error"]
            ):
                raise MailAccountError(
                    tr(
                        "La autorización ha caducado o no pertenece a este navegador. Iníciala de nuevo desde PiVigia."
                    )
                )
            if denied:
                flow["error"] = True
                return
            if not code or len(code) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in code):
                raise MailAccountError(
                    tr("El proveedor devolvió una autorización no válida. Inicia la conexión de nuevo.")
                )
            flow["code"] = code

    def finish(self, state, proof, address, identity, account):
        with self.lock:
            self._expire()
            flow = self.flows.get(state)
            if (
                not flow
                or flow["address"] != address
                or flow["identity"] != identity
                or not hmac.compare_digest(flow["proof"], proof)
                or flow["account"].signature() != account.signature()
            ):
                raise MailAccountError(
                    tr("La autorización ha caducado o cambió la configuración. Vuelve a conectar la cuenta.")
                )
            if flow["mode"] == "device":
                if time.monotonic() < flow["next_poll"]:
                    return {"status": "pending"}
                flow["next_poll"] = time.monotonic() + flow["interval"]
                device = dict(flow)
            else:
                device = None
            if device:
                pass
            elif flow["error"]:
                del self.flows[state]
                raise MailAccountError(tr("No se concedió acceso a la cuenta de correo."))
            elif flow["code"] is None:
                return {"status": "pending"}
            else:
                # Consumir antes de acceder a la red: ningún código se canjea dos veces.
                del self.flows[state]
        if device:
            return self.finish_device(state, device, address, account)
        fields = {
            "grant_type": "authorization_code",
            "client_id": account.client_id,
            "redirect_uri": account.redirect_uri,
            "code": flow["code"],
            "code_verifier": flow["verifier"],
        }
        if account.client_secret:
            fields["client_secret"] = account.client_secret
        tokens = token_request(account.token_endpoint, fields)
        if not tokens["refresh_token"]:
            raise MailAccountError(
                tr("El proveedor no concedió acceso sin conexión. Revisa los permisos y autoriza de nuevo.")
            )
        if not self.store.save_mail_tokens(address, account, tokens):
            raise MailAccountError(
                tr("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada.")
            )
        return {
            "status": "connected",
            "detail": tr("Cuenta autorizada. Prueba la conexión IMAP para verificar usuario y carpeta."),
        }

    def finish_device(self, state, flow, address, account):
        fields = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": account.client_id,
            "device_code": flow["device_code"],
        }
        try:
            tokens = token_request(account.token_endpoint, fields, pending=True)
        except Exception:
            with self.lock:
                self.flows.pop(state, None)
            raise
        with self.lock:
            current = self.flows.get(state)
            if not current:
                raise MailAccountError(
                    tr("La autorización ha caducado o cambió la configuración. Vuelve a conectar la cuenta.")
                )
            if "error" in tokens:
                if tokens["error"] == "slow_down":
                    current["interval"] = min(60, current["interval"] + 5)
                current["next_poll"] = time.monotonic() + current["interval"]
                return {"status": "pending"}
            del self.flows[state]
        if not tokens["refresh_token"]:
            raise MailAccountError(
                tr("El proveedor no concedió acceso sin conexión. Revisa los permisos y autoriza de nuevo.")
            )
        if not self.store.save_mail_tokens(address, account, tokens):
            raise MailAccountError(
                tr("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada.")
            )
        return {
            "status": "connected",
            "detail": tr("Cuenta autorizada. Prueba la conexión IMAP para verificar usuario y carpeta."),
        }

    def access_token(self, address, account):
        tokens = self.store.mail_tokens(address, account.oauth_key())
        if not tokens:
            raise MailAccountError(tr("Conecta la cuenta con OAuth2 antes de consultar el buzón."))
        if tokens["expires_at"] > time.time() + 60:
            return tokens["access_token"]
        fields = {
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": account.client_id,
        }
        if account.client_secret:
            fields["client_secret"] = account.client_secret
        updated = token_request(account.token_endpoint, fields)
        updated["refresh_token"] = updated["refresh_token"] or tokens["refresh_token"]
        if not self.store.save_mail_tokens(address, account, updated):
            raise MailAccountError(
                tr("La cuenta cambió durante la conexión. Vuelve a probar con la configuración guardada.")
            )
        return updated["access_token"]

    def disconnect(self, address):
        with self.lock:
            self.flows = {key: f for key, f in self.flows.items() if f["address"] != address}
        self.store.clear_mail_tokens(address)
