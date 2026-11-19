"""Operaciones administrativas de correo; el callback público nunca guarda tokens por sí solo."""

import hashlib
import html
import json
import logging
import re
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .i18n import tr, translate_saved
from .mail_reader import safe_error
from .mail_network import MailAccountBusy


class OAuthProof(BaseModel):
    flow: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    proof: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class CallbackLogFilter(logging.Filter):
    """Uvicorn no debe registrar códigos de autorización en la URL del callback."""

    def filter(self, record):
        if isinstance(record.args, tuple) and len(record.args) == 5:
            args = list(record.args)
            if isinstance(args[2], str) and "/oauth/callback" in args[2]:
                args[2] = args[2].split("?", 1)[0]
                record.args = tuple(args)
        return True


def cookie_name(state):
    return "pivigia-oauth-" + hashlib.sha256(state.encode()).hexdigest()[:16]


def identity_key(request):
    identity = request.state.identity
    return identity.provider + ":" + identity.user_id


def install_mail_routes(app, reader):
    # Importación tardía para reutilizar el límite de cuerpos sin dependencia circular al cargar módulos.
    from .web import read_body

    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, CallbackLogFilter) for f in logger.filters):
        logger.addFilter(CallbackLogFilter())

    def run(callback, *args):
        try:
            return callback(*args)
        except Exception as error:
            raise HTTPException(
                409 if isinstance(error, MailAccountBusy) else 422, safe_error(error)
            ) from None

    @app.get("/api/mailboxes/external")
    def status():
        result = reader.status()
        for item in result:
            item["detail"] = translate_saved(item["detail"])
        return result

    @app.post("/api/mailboxes/{address}/test")
    def probe(address: str):
        return run(reader.probe, address)

    @app.post("/api/mailboxes/{address}/reset")
    async def reset(address: str, request: Request):
        import asyncio

        try:
            data = json.loads(await read_body(request, 100))
        except ValueError:
            data = None
        if not isinstance(data, dict) or set(data) != {"confirm"} or data["confirm"] is not True:
            raise HTTPException(
                422, tr("Confirma que quieres omitir los mensajes pendientes y empezar desde ahora.")
            )
        return await asyncio.to_thread(run, reader.reset, address)

    @app.post("/api/mailboxes/{address}/oauth/start")
    def start(address: str, request: Request):
        try:
            with reader.operation(address):
                account = reader.account(address).external
                if account.provider != "outlook":
                    callback = urlsplit(account.redirect_uri)
                    origin = request.headers.get("origin", "")
                    # Un retorno a otro sitio no debe recibir la cookie que vincula este navegador.
                    if callback.scheme != "https" or origin != f"{callback.scheme}://{callback.netloc}":
                        raise HTTPException(
                            422,
                            tr(
                                "Abre PiVigia por HTTPS en el mismo dominio y puerto que la URL de retorno OAuth2."
                            ),
                        )
                data, cookie = reader.oauth.begin(address, account, identity_key(request))
            from fastapi.responses import JSONResponse

            response = JSONResponse(data)
            if cookie:
                response.set_cookie(
                    cookie_name(data["flow"]),
                    cookie,
                    max_age=600,
                    secure=True,
                    httponly=True,
                    samesite="lax",
                    path=urlsplit(account.redirect_uri).path,
                )
            return response
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(
                409 if isinstance(error, MailAccountBusy) else 422, safe_error(error)
            ) from None

    @app.post("/api/mailboxes/{address}/oauth/finish")
    async def finish(address: str, request: Request):
        import asyncio

        try:
            proof = OAuthProof.model_validate_json(await read_body(request, 512))
        except ValueError:
            raise HTTPException(422, tr("Petición no válida. Revisa los parámetros enviados.")) from None

        def exchange():
            with reader.operation(address):
                account = reader.account(address).external
                return reader.oauth.finish(proof.flow, proof.proof, address, identity_key(request), account)

        return await asyncio.to_thread(run, exchange)

    @app.post("/api/mailboxes/{address}/oauth/disconnect")
    def disconnect(address: str):
        def revoke():
            with reader.operation(address):
                reader.account(address)
                reader.oauth.disconnect(address)
                return {
                    "ok": True,
                    "detail": tr(
                        "Autorización eliminada de PiVigia. También puedes revocarla en el proveedor."
                    ),
                }

        return run(revoke)

    @app.get("/oauth/callback", response_class=HTMLResponse)
    def callback(request: Request):
        state = request.query_params.get("state", "")
        try:
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", state):
                raise ValueError()
            for key in ("state", "code", "error"):
                if len(request.query_params.getlist(key)) > 1:
                    raise ValueError()
            reader.oauth.callback(
                state,
                request.cookies.get(cookie_name(state)),
                request.query_params.get("code"),
                "error" in request.query_params,
            )
            message = tr("Autorización recibida. Vuelve al panel de PiVigia para completar la conexión.")
            status_code = 200
        except Exception:
            message = tr(
                "La autorización ha caducado o no pertenece a este navegador. Iníciala de nuevo desde PiVigia."
            )
            status_code = 400
        # No incrustar ni códigos, ni estado, ni respuestas del proveedor; limpiar la URL visible.
        response = HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>PiVigia</title>"
            "<script>history.replaceState(null,'',location.pathname)</script>"
            "<h1>PiVigia</h1><p>" + html.escape(message) + "</p>",
            status_code=status_code,
        )
        response.delete_cookie(
            cookie_name(state), path=request.url.path, secure=True, httponly=True, samesite="lax"
        )
        return response
