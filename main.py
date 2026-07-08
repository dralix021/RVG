import asyncio
import json
import os
import hashlib
import secrets
import time
import logging  # ← این خط اضافه شد
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path
from typing import Dict, Optional

import aiofiles
import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException, WebSocket, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

# ====================== Logging ======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("RVG-Gateway")

# ====================== Config ======================
IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="RVG Gateway - DrPhp", docs_url=None, redoc_url=None)
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====================== Paths ======================
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "rvg_state.json"

# ====================== Global State ======================
LINKS: Dict[str, dict] = {}
SUBS: Dict[str, dict] = {}
SESSIONS: Dict[str, float] = {}
connections: Dict[str, dict] = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: defaultdict = defaultdict(int)

http_client: Optional[httpx.AsyncClient] = None

# Locks
SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()

# ====================== Constants ======================
PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"
SESSION_COOKIE = "rvg_session"
SESSION_TTL = 60 * 60 * 24 * 7

# ====================== Helpers ======================
def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()


def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)


def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])


def fmt_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{int(b)} B"
        b /= 1024
    return f"{b:.2f} TB"


def client_ip(request: Request) -> str:
    for header in ("x-forwarded-for", "x-real-ip"):
        if value := request.headers.get(header):
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })


# ====================== Persistence ======================
async def load_state():
    global LINKS, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.loads(await f.read())

            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]

            logger.info(f"State loaded → {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.error(f"Failed to load state: {e}")


async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")


# ====================== Auth ======================
AUTH = {"password_hash": hash_password(CONFIG["admin_password"])}


async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


async def is_valid_session(token: Optional[str]) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True


async def destroy_session(token: Optional[str]):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


# ====================== Link Helpers ======================
def generate_vless_link(uuid: str, host: str, remark: str = "RVG", protocol: str = DEFAULT_PROTOCOL) -> str:
    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none", "security": "tls", "type": "ws",
            "host": host, "path": path, "sni": host,
            "fp": "chrome", "alpn": "http/1.1"
        }
    else:
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none", "security": "tls", "type": "xhttp",
            "mode": mode, "host": host, "path": path, "sni": host,
            "fp": "chrome", "alpn": "h2,http/1.1"
        }

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"


def is_link_expired(link: dict) -> bool:
    if not link.get("expires_at"):
        return False
    try:
        return datetime.now() > datetime.fromisoformat(link["expires_at"])
    except Exception:
        return False


def is_link_allowed(link: Optional[dict]) -> bool:
    if not link or not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    limit = link.get("limit_bytes", 0)
    return limit == 0 or link.get("used_bytes", 0) < limit


# ====================== Default Link ======================
_default_link_created = False


async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return

    async with LINKS_LOCK:
        if any(l.get("is_default") for l in LINKS.values()):
            _default_link_created = True
            return

        uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()[:36]
        uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"

        LINKS[uid] = {
            "label": "لینک پیش‌فرض",
            "limit_bytes": 0,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": None,
            "note": "",
            "is_default": True,
            "sub_id": None,
            "protocol": DEFAULT_PROTOCOL,
        }
        asyncio.create_task(save_state())
        _default_link_created = True


# ====================== Startup / Shutdown ======================
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)

    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True
    )

    await load_state()
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"RVG Gateway v{app.version} started on port {CONFIG['port']}")


@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()


# ====================== Basic Routes ======================
@app.get("/")
async def root():
    return {
        "service": "RVG Gateway",
        "version": app.version,
        "status": "active",
        "channel": "https://t.me/SpareVpn",
        "docs": "Protected",
        "ping": "/ping"
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "connections": len(connections),
        "uptime": f"{int(time.time() - stats['start_time'])}s"
    }


@app.get("/ping")
async def ping():
    return {
        "status": "ok",
        "version": app.version,
        "timestamp": datetime.now(IRAN_TZ).isoformat(),
        "uptime_seconds": int(time.time() - stats["start_time"]),
        "active_connections": len(connections)
    }


# ====================== Subscription Endpoints ======================
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")

    host = get_host()
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    vless = generate_vless_link(uuid, host, f"RVG-{link['label']}", proto)

    content = base64.b64encode(vless.encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={"profile-title": quote(link["label"]), "support-url": "https://t.me/SpareVpn"}
    )


@app.get("/sub-all", dependencies=[Depends(require_auth)])
async def subscription_all():
    import base64
    host = get_host()
    async with LINKS_LOCK:
        lines = [
            generate_vless_link(uid, host, f"RVG-{d['label']}", d.get("protocol", DEFAULT_PROTOCOL))
            for uid, d in LINKS.items() if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")


# ====================== Auth Endpoints ======================
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="strict", path="/")
    return resp


@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ====================== HTML Pages ======================
from pages import LOGIN_HTML, DASHBOARD_HTML


@app.get("/admin-login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/admin-login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/login", response_class=HTMLResponse)
async def old_login_redirect():
    return RedirectResponse(url="/admin-login")


# ====================== Import External Modules ======================
from relay_vless import websocket_tunnel
from xhttp_siz10 import router as xhttp_router
from pages import get_public_page_html

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)
app.include_router(xhttp_router)

# ====================== Run ======================
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=CONFIG["port"],
        log_level="info",
        workers=1,
        timeout_keep_alive=65
    )
