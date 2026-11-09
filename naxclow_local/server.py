"""Naxclow Local - emulează cloud-ul Naxclow (home.naxclow.com) în LAN.

- HTTP :80  POST /app/api/ApiAlertRecord/v6SendAlert -> salvează poza, trimite eveniment în HA
- HTTP :80  orice alt endpoint -> logat (pentru reverse engineering), răspuns generic OK
- TCP :29838 -> captură brută (canalul video/comenzi, încă necunoscut)
"""
import asyncio
import base64
import binascii
import json
import logging
import os
import secrets
import socket
import time
import urllib.parse
from pathlib import Path

from aiohttp import ClientSession, web

LOG = logging.getLogger("naxclow")
TCP_PORT = int(os.environ.get("TCP_PORT", "29838"))
TCP_HOST = os.environ.get("TCP_HOST", "").strip()
TCP_CAPTURE = os.environ.get("TCP_CAPTURE", "true").lower() == "true"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
HA_API = os.environ.get("HA_API", "http://supervisor/core/api")
WWW = Path(os.environ.get("WWW_DIR", "/homeassistant/www/naxclow"))
SHARE = Path(os.environ.get("SHARE_DIR", "/share/naxclow"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))

# Setările întoarse de cloud (copiate din răspunsul real)
SETTINGS = [
    {"isAlert": False, "isEnable": False, "settingQuency": 15, "isShare": False, "settingType": "移动预测"},
    {"isAlert": True, "isEnable": False, "settingQuency": 1000, "isShare": False, "settingType": "按铃通知"},
    {"isAlert": False, "isEnable": False, "settingQuency": 1000, "isShare": False, "settingType": "脱落通知"},
    {"isAlert": True, "isEnable": False, "settingQuency": 1000, "isShare": False, "settingType": "红外补光"},
    {"isAlert": False, "isEnable": False, "settingQuency": 1000, "isShare": True, "settingType": "微信推送"},
    {"isAlert": True, "isEnable": False, "settingQuency": 1000, "isShare": True, "settingType": "app推送"},
    {"isAlert": False, "isEnable": False, "settingQuency": 1000, "isShare": False, "settingType": "防盗锁"},
    {"isAlert": False, "isEnable": False, "settingParam": "0", "settingQuency": 1000, "isShare": True, "settingType": "设备管理权限"},
    {"isAlert": True, "isEnable": False, "settingParam": "0", "settingQuency": 0, "isShare": True, "settingType": "低电提醒"},
]


def local_ip():
    if TCP_HOST:
        return TCP_HOST
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def parse_form(raw: bytes) -> dict:
    # base64 nu e URL-encoded de dispozitiv ('+' rămâne '+'), deci nu folosim parse_qs
    out = {}
    for part in raw.decode("latin1").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v if k == "base64" else urllib.parse.unquote_plus(v)
    return out


async def fire_event(data: dict):
    if not SUPERVISOR_TOKEN:
        LOG.warning("Fără SUPERVISOR_TOKEN, nu trimit eveniment: %s", data)
        return
    try:
        async with ClientSession() as s:
            async with s.post(
                f"{HA_API}/events/naxclow_alert",
                json=data,
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
                timeout=5,
            ) as r:
                LOG.debug("Eveniment HA: %s", r.status)
    except Exception as e:  # noqa: BLE001
        LOG.error("Eroare eveniment HA: %s", e)


def save_image(dev: str, b64: str) -> str | None:
    if not b64:
        return None
    try:
        img = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except (binascii.Error, ValueError) as e:
        LOG.warning("base64 invalid: %s", e)
        return None
    if not img.startswith(b"\xff\xd8"):
        LOG.warning("Imagine non-JPEG (%d bytes)", len(img))
    d = WWW / dev
    d.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    (d / f"{ts}.jpg").write_bytes(img)
    (d / "last.jpg").write_bytes(img)
    # păstrează ultimele 50
    files = sorted(p for p in d.glob("2*.jpg"))
    for p in files[:-50]:
        p.unlink(missing_ok=True)
    return f"/local/naxclow/{dev}/{ts}.jpg"


async def alert(request: web.Request):
    raw = await request.read()
    f = parse_form(raw)
    dev = f.get("devicesCode", "unknown")
    url = save_image(dev, f.get("base64", ""))
    ev = {
        "device": dev,
        "record_type": f.get("recordType"),
        "type": f.get("type"),
        "battery_mv": int(f["battery"]) if f.get("battery", "").isdigit() else None,
        "image": url,
        "fields": {k: v for k, v in f.items() if k not in ("base64", "token")},
    }
    LOG.info("ALERTĂ %s type=%s battery=%s img=%s", dev, ev["type"], ev["battery_mv"], url)
    asyncio.create_task(fire_event(ev))
    resp = {
        "isLock": False,
        "random": secrets.randbelow(10**9),
        "eventId": secrets.token_hex(16),
        "code": 200,
        "data": SETTINGS,
        "updateUrl": None,
        "conf": {
            "tcpPort": TCP_PORT,
            "uid": dev,
            "domain": "home.naxclow.com",
            "host": local_ip(),
            "pwd": secrets.token_hex(4),
        },
        "id": secrets.token_hex(16),
        "message": "操作成功",
        "version": None,
    }
    return web.json_response(resp, dumps=lambda o: json.dumps(o, ensure_ascii=False, separators=(",", ":")))


async def catch_all(request: web.Request):
    body = await request.read()
    LOG.warning(
        "NECUNOSCUT %s %s headers=%s body=%r",
        request.method, request.path_qs, dict(request.headers), body[:500],
    )
    SHARE.mkdir(parents=True, exist_ok=True)
    with open(SHARE / "http_unknown.log", "a") as fh:
        fh.write(f"{time.strftime('%F %T')} {request.method} {request.path_qs}\n{dict(request.headers)}\n{body[:4000]!r}\n\n")
    return web.json_response({"code": 200, "message": "操作成功", "data": None})


async def tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    LOG.info("TCP conectat: %s", peer)
    SHARE.mkdir(parents=True, exist_ok=True)
    fn = SHARE / f"tcp_{time.strftime('%Y%m%d_%H%M%S')}_{peer[0]}.bin"
    total = 0
    try:
        with open(fn, "wb") as fh:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                total += len(data)
                if TCP_CAPTURE:
                    fh.write(data)
                    fh.flush()
                if total <= 4096:
                    LOG.info("TCP %s <- %d B: %s", peer[0], len(data), data[:64].hex(" "))
    except Exception as e:  # noqa: BLE001
        LOG.info("TCP %s eroare: %s", peer, e)
    finally:
        LOG.info("TCP închis: %s (%d B, %s)", peer, total, fn.name)
        writer.close()


async def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "info").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_post("/app/api/ApiAlertRecord/v6SendAlert", alert)
    app.router.add_route("*", "/{tail:.*}", catch_all)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", HTTP_PORT).start()
    LOG.info("HTTP pe :%d, IP anunțat soneriei: %s", HTTP_PORT, local_ip())
    srv = await asyncio.start_server(tcp_handler, "0.0.0.0", TCP_PORT)
    LOG.info("TCP pe :%d (capture=%s)", TCP_PORT, TCP_CAPTURE)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
