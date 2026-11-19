"""Persistencia SQLite privada: un proceso por directorio, transacciones y cola durable."""
import os
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config import Settings, data_dir
from .server import ServerSettings
from .i18n import tr
from .mail_secrets import MailSecrets


class Store:
    def __init__(self, path=None):
        self.path = Path(path) if path else data_dir()
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(mode=...) no corrige instalaciones existentes; cerrar el directorio antes de abrir SQLite.
        self.path.chmod(0o700)
        self.db_path = self.path / "pivigia.sqlite3"
        if self.db_path.exists():
            self.db_path.chmod(0o600)
        with self.db() as db:
            db.executescript("""
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, created REAL NOT NULL, updated REAL NOT NULL,
                mailbox TEXT NOT NULL, sender TEXT NOT NULL, raw BLOB,
                status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
                next_try REAL NOT NULL DEFAULT 0, result TEXT NOT NULL DEFAULT '{}',
                error TEXT NOT NULL DEFAULT '', delivered TEXT NOT NULL DEFAULT '[]');
              CREATE TABLE IF NOT EXISTS camera_events (
                id INTEGER PRIMARY KEY, created REAL NOT NULL, camera_id TEXT NOT NULL,
                camera_name TEXT NOT NULL, kind TEXT NOT NULL, detections TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS recent_detections (
                category TEXT PRIMARY KEY, last_seen REAL NOT NULL);
              CREATE TABLE IF NOT EXISTS mail_sync (
                mailbox TEXT PRIMARY KEY, source TEXT NOT NULL, uidvalidity INTEGER NOT NULL,
                last_uid INTEGER NOT NULL, checked REAL NOT NULL DEFAULT 0,
                imported INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE IF NOT EXISTS mail_tokens (
                mailbox TEXT PRIMARY KEY, binding TEXT NOT NULL, value TEXT NOT NULL);
            """)
            db.execute("INSERT OR IGNORE INTO settings VALUES (1, ?)", (Settings().model_dump_json(),))
            db.execute("UPDATE jobs SET status='queued' WHERE status='processing'")
            encrypted = db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0]
            needs_key = "enc:v1:" in encrypted or bool(db.execute("SELECT 1 FROM mail_tokens LIMIT 1").fetchone())
        os.chmod(self.db_path, 0o600)
        self.mail_secrets = MailSecrets(self.path, required=needs_key)
        self.token_path = self.path / "admin-token"
        if not self.token_path.exists():
            fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(os.environ.get("PIVIGIA_ADMIN_TOKEN") or secrets.token_urlsafe(32))
        self.token_path.chmod(0o600)
        self.token = (os.environ.get("PIVIGIA_ADMIN_TOKEN") or self.token_path.read_text()).strip()
        if len(self.token) < 16:
            raise ValueError(tr("El token de administración debe tener al menos 16 caracteres"))

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def settings(self):
        with self.db() as db:
            return self._settings(db)

    def _settings(self, db):
        data = json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])
        return Settings.model_validate(self.mail_secrets.settings(data, decrypt=True))

    def save_settings(self, settings):
        data = self.mail_secrets.settings(settings.model_dump())
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(data),))
            # Retirar los tokens de cuentas eliminadas o convertidas a entrada local.
            keep = {b.address: b.external.oauth_key() for b in settings.mailboxes
                    if b.source == "imap" and b.external.auth == "oauth2"}
            for address, binding in db.execute("SELECT mailbox,binding FROM mail_tokens").fetchall():
                if keep.get(address) != binding:
                    db.execute("DELETE FROM mail_tokens WHERE mailbox=?", (address,))
            active = {b.address for b in settings.mailboxes if b.source == "imap"}
            for (address,) in db.execute("SELECT mailbox FROM mail_sync").fetchall():
                if address not in active:
                    db.execute("DELETE FROM mail_sync WHERE mailbox=?", (address,))

    def external_current(self, db, address, signature, *, enabled=False):
        """Comprueba bajo transacción que la cuenta no cambió durante una operación de red."""
        return next((b for b in self._settings(db).mailboxes
                     if b.address == address and b.source == "imap"
                     and (b.enabled or not enabled) and b.external.signature() == signature), None)

    def mail_tokens(self, address, binding):
        with self.db() as db:
            row = db.execute("SELECT binding,value FROM mail_tokens WHERE mailbox=?", (address,)).fetchone()
        if row and row[0] == binding:
            return self.mail_secrets.decrypt(row[1], "oauth:" + address + ":" + binding)
        return None

    def save_mail_tokens(self, address, account, value):
        binding = account.oauth_key()
        encrypted = self.mail_secrets.encrypt(value, "oauth:" + address + ":" + binding)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.external_current(db, address, account.signature()):
                return False
            db.execute("INSERT OR REPLACE INTO mail_tokens VALUES(?,?,?)", (address, binding, encrypted))
        return True

    def clear_mail_tokens(self, address):
        with self.db() as db:
            db.execute("DELETE FROM mail_tokens WHERE mailbox=?", (address,))

    def mail_position(self, address):
        with self.db() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM mail_sync WHERE mailbox=?", (address,)).fetchone()
            return dict(row) if row else None

    def begin_mail_sync(self, address, account, uidvalidity, last_uid, *, reset=False):
        """Fija el punto inicial sin importar correo antiguo; un reset requiere acción explícita."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.external_current(db, address, account.signature(), enabled=True):
                return False
            previous = db.execute("SELECT source FROM mail_sync WHERE mailbox=?", (address,)).fetchone()
            if previous and previous[0] == account.source_key() and not reset:
                return False
            db.execute("INSERT OR REPLACE INTO mail_sync(mailbox,source,uidvalidity,last_uid,checked)"
                       " VALUES(?,?,?,?,?)", (address, account.source_key(), uidvalidity, last_uid, time.time()))
        return True

    def import_mail(self, address, account, uidvalidity, previous_uid, uid, raw=None, *, skipped=False):
        """Cola y cursor se confirman juntos: un reinicio no pierde ni duplica una importación."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            box = self.external_current(db, address, account.signature(), enabled=True)
            row = db.execute("SELECT source,uidvalidity,last_uid FROM mail_sync WHERE mailbox=?",
                             (address,)).fetchone()
            if not box or row != (account.source_key(), uidvalidity, previous_uid) or uid <= previous_uid:
                return "changed"
            now = time.time()
            if raw is not None:
                limit = self._settings(db).queue_limit
                if db.execute("SELECT count(*) FROM jobs WHERE raw IS NOT NULL").fetchone()[0] >= limit:
                    return "full"
                # El trabajador analiza el MIME con los mismos límites que para SMTP local.
                db.execute("INSERT INTO jobs(created,updated,mailbox,sender,raw) VALUES(?,?,?,?,?)",
                           (now, now, address, "", raw))
            db.execute("UPDATE mail_sync SET last_uid=?,checked=?,imported=imported+?,skipped=skipped+?"
                       " WHERE mailbox=?", (uid, now, int(raw is not None), int(skipped), address))
        return "ok"

    def mail_checked(self, address):
        with self.db() as db:
            db.execute("UPDATE mail_sync SET checked=? WHERE mailbox=?", (time.time(), address))

    def server_settings(self):
        with self.db() as db:
            row = db.execute("SELECT value FROM settings WHERE id=2").fetchone()
        return ServerSettings.model_validate_json(row[0]) if row else ServerSettings()

    def save_server_settings(self, settings):
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES(2, ?)", (settings.model_dump_json(),))

    def enqueue(self, address, sender, raw, limit, *, local_only=False):
        """Reserva capacidad y añade el original en la misma transacción de escritura."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if local_only and not any(b.address == address and b.enabled and b.source == "local"
                                      for b in self._settings(db).mailboxes):
                return None
            count = db.execute("SELECT count(*) FROM jobs WHERE raw IS NOT NULL").fetchone()[0]
            if count >= limit:
                return False
            now = time.time()
            db.execute(
                "INSERT INTO jobs(created,updated,mailbox,sender,raw) VALUES(?,?,?,?,?)",
                (now, now, address, sender, raw),
            )
        return True

    def claim(self):
        """Reclama el trabajo disponible más antiguo sin permitir una doble selección."""
        with self.db() as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN IMMEDIATE")
            job = db.execute(
                "SELECT * FROM jobs WHERE status='queued' AND next_try<=? ORDER BY id LIMIT 1", (time.time(),)
            ).fetchone()
            if job:
                db.execute(
                    "UPDATE jobs SET status='processing',updated=? WHERE id=?", (time.time(), job["id"])
                )
                return dict(job)

    def update(self, job_id, **values):
        allowed = {"status", "attempts", "next_try", "result", "error", "raw", "delivered"}
        if not values.keys() <= allowed:
            raise ValueError(tr("Campo no permitido"))
        values["updated"] = time.time()
        with self.db() as db:
            if "result" in values:
                previous = db.execute("SELECT result FROM jobs WHERE id=?", (job_id,)).fetchone()
                result = json.loads(values["result"])
                if previous and json.loads(previous[0]).get("schema") != 2 and result.get("schema") == 2:
                    self._record_detections(db, result.get("detections", []), False, values["updated"])
            db.execute(
                "UPDATE jobs SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?",
                [*values.values(), job_id],
            )

    def events(self):
        with self.db() as db:
            db.row_factory = sqlite3.Row
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id,created,mailbox,status,attempts,result,error,delivered FROM jobs ORDER BY id DESC LIMIT 100"
                )
            ]

    def stats(self):
        with self.db() as db:
            return dict(db.execute("SELECT status,count(*) FROM jobs GROUP BY status"))

    @staticmethod
    def _record_detections(db, detections, motion, now):
        categories = {d.get("category") for d in detections} & {"person", "car", "animal"}
        if motion:
            categories.add("motion")
        for category in categories:
            db.execute("INSERT INTO recent_detections(category,last_seen) VALUES(?,?) "
                       "ON CONFLICT(category) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)",
                       (category, now))

    def record_detections(self, detections, motion=False):
        with self.db() as db:
            self._record_detections(db, detections, motion, time.time())

    def detection_status(self):
        now, window = time.time(), 120
        with self.db() as db:
            latest = dict(db.execute("SELECT category,last_seen FROM recent_detections"))
        return {"window_seconds": window, "categories": {
            category: {"last_seen": latest.get(category),
                       "recent": category in latest and 0 <= now - latest[category] < window}
            for category in ("person", "car", "animal", "motion")}}

    def cleanup(self, days):
        with self.db() as db:
            db.execute(
                "DELETE FROM jobs WHERE created < ? AND status NOT IN ('queued','processing')",
                (time.time() - days * 86400,),
            )
            db.execute("DELETE FROM camera_events WHERE created < ?", (time.time() - days * 86400,))
            db.execute("DELETE FROM recent_detections WHERE last_seen < ?", (time.time() - days * 86400,))

    def camera_event(self, camera, kind, detections):
        import json

        with self.db() as db:
            db.execute(
                "INSERT INTO camera_events(created,camera_id,camera_name,kind,detections) VALUES(?,?,?,?,?)",
                (time.time(), camera.id, camera.name, kind, json.dumps(detections)),
            )

    def camera_events(self):
        import json

        with self.db() as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM camera_events ORDER BY id DESC LIMIT 100").fetchall()
            return [{**dict(row), "detections": json.loads(row["detections"])} for row in rows]

    def retry(self, job_id):
        with self.db() as db:
            return db.execute(
                "UPDATE jobs SET status='queued',attempts=0,next_try=0,error='' "
                "WHERE id=? AND status='failed' AND raw IS NOT NULL",
                (job_id,),
            ).rowcount
