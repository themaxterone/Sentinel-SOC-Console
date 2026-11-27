import contextvars
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import msal
from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, abort, current_app, jsonify, redirect, request, session, url_for


AUTH_MODE = os.environ.get("SOC_AUTH_MODE", "local").strip().lower()
if AUTH_MODE not in {"local", "entra"}:
    raise RuntimeError("SOC_AUTH_MODE must be 'local' or 'entra'.")

DATA_ROOT = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).parent)).resolve()
AUTH_DATABASE = Path(
    os.environ.get("SOC_AUTH_DATABASE", DATA_ROOT / "soc-auth.sqlite3")
).resolve()
_current_user = contextvars.ContextVar("soc_current_user", default=None)
_token_locks = {}
_token_locks_guard = threading.Lock()
_entra_settings = {}

GRAPH_SCOPES = [
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/IdentityRiskyUser.Read.All",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/ThreatHunting.Read.All",
]
LOG_ANALYTICS_SCOPES = ["https://api.loganalytics.io/.default"]
AZURE_ARM_SCOPES = ["https://management.azure.com/.default"]
AUTH_RESOURCES = {
    "graph": GRAPH_SCOPES,
    "log-analytics": LOG_ANALYTICS_SCOPES,
    "azure-arm": AZURE_ARM_SCOPES,
}


class UserAuthorizationRequired(Exception):
    def __init__(self, resource):
        self.resource = resource
        super().__init__(f"Connect your Microsoft {resource} account before running this action.")


def current_user_id():
    if AUTH_MODE == "local":
        return "local"
    return session.get("user_id")


def current_job_user_id():
    return _current_user.get()


@contextmanager
def user_context(user_id):
    token = _current_user.set(user_id)
    try:
        yield
    finally:
        _current_user.reset(token)


def _token_lock(user_id):
    with _token_locks_guard:
        return _token_locks.setdefault(user_id, threading.RLock())


def _fernet():
    key = os.environ.get("SOC_TOKEN_ENCRYPTION_KEY", "")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise RuntimeError("SOC_TOKEN_ENCRYPTION_KEY must be a valid Fernet key.") from error


def _connect_database():
    AUTH_DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(AUTH_DATABASE, timeout=30)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS user_token_cache "
        "(user_id TEXT PRIMARY KEY, encrypted_cache BLOB NOT NULL)"
    )
    return connection


@contextmanager
def _database():
    connection = _connect_database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _load_cache(user_id):
    cache = msal.SerializableTokenCache()
    with _database() as connection:
        row = connection.execute(
            "SELECT encrypted_cache FROM user_token_cache WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    if row:
        try:
            serialized = _fernet().decrypt(row[0]).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as error:
            raise RuntimeError("Unable to decrypt the stored Microsoft token cache.") from error
        cache.deserialize(serialized)
    return cache


def _save_cache(user_id, cache):
    if not cache.has_state_changed:
        return
    encrypted = _fernet().encrypt(cache.serialize().encode("utf-8"))
    with _database() as connection:
        connection.execute(
            "INSERT INTO user_token_cache (user_id, encrypted_cache) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET encrypted_cache = excluded.encrypted_cache",
            (user_id, encrypted),
        )


def _client(cache=None):
    return msal.ConfidentialClientApplication(
        client_id=_entra_settings["client_id"],
        authority=f"https://login.microsoftonline.com/{_entra_settings['tenant_id']}",
        client_credential=_entra_settings["client_secret"],
        token_cache=cache,
    )


def acquire_user_token(user_id, scopes):
    if not user_id:
        raise UserAuthorizationRequired("Graph")
    resources = [
        resource for resource, resource_scopes in AUTH_RESOURCES.items()
        if set(scopes).issubset(resource_scopes)
    ]
    resource = resources[0] if resources else "Graph"

    with _token_lock(user_id):
        cache = _load_cache(user_id)
        client = _client(cache)
        accounts = client.get_accounts()
        account = next(
            (
                item for item in accounts
                if str(item.get("local_account_id", "")).lower() == user_id.lower()
            ),
            None,
        )
        if account:
            result = client.acquire_token_silent(scopes, account=account)
            if result and result.get("access_token"):
                _save_cache(user_id, cache)
                return result["access_token"]
        raise UserAuthorizationRequired(resource)


def require_resource_access(resource):
    if AUTH_MODE == "local":
        return None
    if resource not in AUTH_RESOURCES:
        raise ValueError(f"Unknown Microsoft authorization resource: {resource}")
    try:
        acquire_user_token(current_user_id(), AUTH_RESOURCES[resource])
    except UserAuthorizationRequired:
        consent_url = url_for(
            "auth.connect_resource",
            resource=resource,
            next=url_for("home"),
        )
        return jsonify({
            "error": f"Connect your Microsoft {resource} account, then retry the action.",
            "authorization_required": True,
            "authorization_url": consent_url,
        }), 428
    return None


def _safe_return_path(candidate):
    if not candidate or not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate:
        return url_for("home")
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return url_for("home")
    return candidate


def register_auth(app):
    if AUTH_MODE == "local":
        app.secret_key = os.environ.get("SOC_SESSION_SECRET") or os.urandom(32)
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )
        return

    required = {
        "SOC_SESSION_SECRET": os.environ.get("SOC_SESSION_SECRET"),
        "SOC_TENANT_ID": os.environ.get("SOC_TENANT_ID"),
        "SOC_CLIENT_ID": os.environ.get("SOC_CLIENT_ID"),
        "SOC_CLIENT_SECRET": os.environ.get("SOC_CLIENT_SECRET"),
        "SOC_REDIRECT_URI": os.environ.get("SOC_REDIRECT_URI"),
        "SOC_TOKEN_ENCRYPTION_KEY": os.environ.get("SOC_TOKEN_ENCRYPTION_KEY"),
        "SOC_ALLOWED_HOSTS": os.environ.get("SOC_ALLOWED_HOSTS"),
        "SOC_TRUST_PROXY": os.environ.get("SOC_TRUST_PROXY"),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError(
            "Entra mode is fail-closed. Configure the required environment variables: "
            + ", ".join(missing)
        )
    if required["SOC_TRUST_PROXY"] != "1":
        raise RuntimeError(
            "Entra mode requires SOC_TRUST_PROXY=1 and a reverse proxy that terminates HTTPS "
            "and overwrites forwarded headers."
        )
    for key in ("SOC_TENANT_ID", "SOC_CLIENT_ID"):
        try:
            uuid.UUID(required[key])
        except ValueError as error:
            raise RuntimeError(f"{key} must be a GUID.") from error
    allowed_hosts = {
        host.strip().lower()
        for host in required["SOC_ALLOWED_HOSTS"].split(",")
        if host.strip()
    }
    redirect_uri = urlsplit(required["SOC_REDIRECT_URI"])
    if (
        len(required["SOC_SESSION_SECRET"]) < 32
        or redirect_uri.scheme != "https"
        or not redirect_uri.hostname
        or redirect_uri.hostname.lower() not in allowed_hosts
        or redirect_uri.path != "/auth/callback"
        or redirect_uri.query
        or redirect_uri.fragment
    ):
        raise RuntimeError(
            "Configure a 32-character session secret and an HTTPS SOC_REDIRECT_URI on an allowed host "
            "with the /auth/callback path."
        )

    _fernet()
    app.secret_key = required["SOC_SESSION_SECRET"]
    app.config.update(
        ENTRA_TENANT_ID=required["SOC_TENANT_ID"],
        ENTRA_CLIENT_ID=required["SOC_CLIENT_ID"],
        ENTRA_CLIENT_SECRET=required["SOC_CLIENT_SECRET"],
        ENTRA_REDIRECT_URI=required["SOC_REDIRECT_URI"],
        ALLOWED_HOSTS=allowed_hosts,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    _entra_settings.update(
        tenant_id=required["SOC_TENANT_ID"],
        client_id=required["SOC_CLIENT_ID"],
        client_secret=required["SOC_CLIENT_SECRET"],
        redirect_uri=required["SOC_REDIRECT_URI"],
    )
    with _database():
        pass

    blueprint = Blueprint("auth", __name__)

    def begin_flow(kind, resource=None, return_to=None):
        cache = _load_cache(session["user_id"]) if session.get("user_id") else msal.SerializableTokenCache()
        scopes = ["openid", "profile", "email"]
        if resource:
            scopes.extend(AUTH_RESOURCES[resource])
        flow = _client(cache).initiate_auth_code_flow(
            scopes=scopes,
            redirect_uri=_entra_settings["redirect_uri"],
            prompt="select_account" if kind == "login" else None,
        )
        session["oauth_flow"] = flow
        session["oauth_kind"] = kind
        session["oauth_resource"] = resource
        session["oauth_return_to"] = _safe_return_path(return_to)
        return redirect(flow["auth_uri"])

    @blueprint.get("/login")
    def login():
        session.clear()
        return begin_flow("login")

    @blueprint.get("/connect/<resource>")
    def connect_resource(resource):
        if resource not in AUTH_RESOURCES:
            abort(404)
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return begin_flow(
            "connect",
            resource=resource,
            return_to=request.args.get("next"),
        )

    @blueprint.get("/callback")
    def callback():
        flow = session.pop("oauth_flow", None)
        kind = session.pop("oauth_kind", None)
        session.pop("oauth_resource", None)
        return_to = session.pop("oauth_return_to", url_for("home"))
        if not flow or kind not in {"login", "connect"}:
            abort(400, "The sign-in flow expired. Start again.")

        user_id = session.get("user_id") if kind == "connect" else None
        cache = _load_cache(user_id) if user_id else msal.SerializableTokenCache()
        try:
            result = _client(cache).acquire_token_by_auth_code_flow(flow, request.args)
        except ValueError:
            abort(400, "Microsoft sign-in validation failed. Start again.")
        if "error" in result:
            abort(401, result.get("error_description", "Microsoft sign-in was not completed."))

        claims = result.get("id_token_claims", {})
        if claims.get("tid", "").lower() != _entra_settings["tenant_id"].lower():
            abort(403, "Sign in with an account from the configured Microsoft tenant.")
        account_id = claims.get("oid") or claims.get("sub")
        if not account_id:
            abort(401, "Microsoft did not return a stable user identifier.")
        account_id = str(account_id).lower()
        if kind == "connect" and account_id != str(user_id).lower():
            abort(403, "The selected Microsoft account does not match the signed-in user.")

        if kind == "login":
            session.clear()
            session["user_id"] = account_id
            session["user_name"] = (
                claims.get("name")
                or claims.get("preferred_username")
                or "SOC user"
            )
            session.permanent = True
        _save_cache(account_id, cache)
        return redirect(_safe_return_path(return_to))

    @blueprint.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("auth.login"))

    app.register_blueprint(blueprint, url_prefix="/auth")

    @app.before_request
    def require_signed_in_user():
        if request.endpoint == "static" or request.blueprint == "auth":
            return None
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Sign in with Microsoft to continue."}), 401
            return redirect(url_for("auth.login"))
        return None
