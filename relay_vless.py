# relay_vless.py
"""
VLESS Relay Module - RVG Gateway
بهینه‌سازی شده برای عملکرد بالا، خوانایی و نگهداری
"""

import asyncio
import secrets
from datetime import datetime
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    save_state,
    log_activity,
    now_ir,
)

# ====================== Constants ======================
RELAY_BUF = 256 * 1024  # 256 KB — بهینه برای throughput بالا
CONNECTION_TIMEOUT = 15.0
TCP_CONNECT_TIMEOUT = 10.0


# ====================== Helpers ======================
def _get_client_ip(ws: WebSocket) -> str:
    """دریافت IP واقعی با در نظر گرفتن هدرهای پراکسی (Railway/Cloudflare)"""
    for header in ("x-forwarded-for", "x-real-ip"):
        if value := ws.headers.get(header):
            return value.split(",")[0].strip()
    return ws.client.host if ws.client else "unknown"


async def parse_vless_header(chunk: bytes):
    """پارس هدر VLESS با مدیریت خطا"""
    if len(chunk) < 24:
        raise ValueError("Header too small")

    try:
        pos = 1
        pos += 16  # UUID
        addon_len = chunk[pos]
        pos += 1 + addon_len
        command = chunk[pos]
        pos += 1
        port = int.from_bytes(chunk[pos:pos + 2], "big")
        pos += 2
        addr_type = chunk[pos]
        pos += 1

        if addr_type == 1:  # IPv4
            address = ".".join(str(b) for b in chunk[pos:pos + 4])
            pos += 4
        elif addr_type == 2:  # Domain
            dlen = chunk[pos]
            pos += 1
            address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore")
            pos += dlen
        elif addr_type == 3:  # IPv6
            ab = chunk[pos:pos + 16]
            address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
            pos += 16
        else:
            raise ValueError(f"Unknown address type: {addr_type}")

        return command, address, port, chunk[pos:]

    except Exception as e:
        raise ValueError(f"Failed to parse VLESS header: {e}") from e


async def check_and_use(uid: str, n: int) -> bool:
    """بررسی quota و ثبت مصرف"""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not is_link_allowed(link):
            return False

        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
        return True


# ====================== Relay Functions ======================
async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    """رله از WebSocket به TCP"""
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break

            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue

            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota exceeded or inactive")
                break

            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)

            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF // 2:
                await writer.drain()

    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as e:
        logger.debug(f"WS→TCP error [{conn_id}]: {e}")
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    """رله از TCP به WebSocket"""
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break

            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota exceeded or inactive")
                break

            connections[conn_id]["bytes"] += len(data)

            payload = (b"\x00\x00" + data) if first else data
            first = False

            await ws.send_bytes(payload)

    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as e:
        logger.debug(f"TCP→WS error [{conn_id}]: {e}")


# ====================== Main Tunnel ======================
async def websocket_tunnel(ws: WebSocket, uuid: str):
    """Main VLESS WebSocket Tunnel"""
    await ws.accept()

    # بررسی اولیه لینک
    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 Connection rejected - uuid={uuid[:8]}… (inactive/expired/quota)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _get_client_ip(ws)
    conn_id = secrets.token_urlsafe(8)

    # ثبت اتصال
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }

    logger.info(f"✅ New WS connection [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label', '?')})", "info")

    writer: Optional[asyncio.StreamWriter] = None

    try:
        # دریافت اولین پیام (هدر VLESS)
        first_msg = await asyncio.wait_for(ws.receive(), timeout=CONNECTION_TIMEOUT)
        if first_msg["type"] == "websocket.disconnect":
            return

        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota exceeded")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)

        logger.info(f"➡️ [{conn_id}] Connecting to {address}:{port}")

        # اتصال به مقصد
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=TCP_CONNECT_TIMEOUT
        )

        # بهینه‌سازی TCP
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload:
            writer.write(payload)
            await writer.drain()

        # اجرای همزمان دو طرف رله
        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )

        # پاکسازی taskهای باقی‌مانده
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "timeout", "uuid": uuid[:8], "time": datetime.now().isoformat()})
        logger.warning(f"⏱️ Timeout on connection [{conn_id}]")

    except WebSocketDisconnect:
        pass

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "uuid": uuid[:8], "time": datetime.now().isoformat()})
        logger.error(f"❌ WS Tunnel error [{conn_id}]: {exc}")

    finally:
        # پاکسازی اتصال
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        connections.pop(conn_id, None)
        logger.info(f"🔌 Connection closed [{conn_id}] remaining={len(connections)}")


# ====================== Export ======================
__all__ = ["websocket_tunnel"]
