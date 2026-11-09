"""Naxclow Local - emulează / interceptează cloud-ul Naxclow (home.naxclow.com) în LAN.

Moduri:
  local - răspunde singur (fără internet). TCP doar capturat.
  proxy - MITM: HTTP și TCP sunt trimise la cloud-ul real, iar traficul e logat
          (aplicația vendorului merge în continuare). conf.host e rescris spre noi.

Peste tot: pozele din alerte se salvează local și se trimite evenimentul `naxclow_alert` în HA.
Cadru TCP: header 20 B (uint32 LE lungime payload + 16 B) + payload (de obicei JSON).
"""
import asyncio
import base64
import binascii
import json
import logging
import os
import secrets
import socket
import struct
import time
import urllib.parse
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, web

from local_hub import LocalHub

LOG = logging.getLogger("naxclow")
MODE = os.environ.get("MODE", "local").strip()
TCP_PORT = int(os.environ.get("TCP_PORT", "29838"))
TCP_HOST = os.environ.get("TCP_HOST", "").strip()
TCP_CAPTURE = os.environ.get("TCP_CAPTURE", "true").lower() == "true"
UPSTREAM_HTTP = os.environ.get("UPSTREAM_HTTP", "47.251.54.125").strip()
UPSTREAM_TCP = os.environ.get("UPSTREAM_TCP", "107.149.136.10:29838").strip()
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
HA_API = os.environ.get("HA_API", "http://supervisor/core/api")
WWW = Path(os.environ.get("WWW_DIR", "/homeassistant/www/naxclow"))
SHARE = Path(os.environ.get("SHARE_DIR", "/share/naxclow"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))
AUTO_STREAM = int(os.environ.get("AUTO_STREAM", "20"))
MAX_STREAM = int(os.environ.get("MAX_STREAM", "60"))
HUB: LocalHub | None = None

# uid -> (host, port) real, învățat din răspunsurile cloud
REAL_TCP: dict[str, tuple[str, int]] = {}

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

SECRET_KEYS = ("token", "pwd", "password")


def jdump(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def redact(o):
    if isinstance(o, dict):
        return {k: ("***" if k in SECRET_KEYS else redact(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact(x) for x in o]
    return o


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


def journal(line: str):
    SHARE.mkdir(parents=True, exist_ok=True)
    with open(SHARE / "journal.log", "a") as fh:
        fh.write(f"{time.strftime('%F %T')} {line}\n")


def parse_form(raw: bytes) -> dict:
    out = {}
    for part in raw.decode("latin1").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v if k == "base64" else urllib.parse.unquote_plus(v)
    return out


async def fire_event(data: dict):
    if not SUPERVISOR_TOKEN:
        LOG.debug("Fără SUPERVISOR_TOKEN, nu trimit eveniment")
        return
    try:
        async with ClientSession() as s:
            async with s.post(
                f"{HA_API}/events/naxclow_alert",
                json=data,
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
                timeout=ClientTimeout(total=5),
            ) as r:
                LOG.debug("Eveniment HA: %s", r.status)
    except Exception as e:  # noqa: BLE001
        LOG.error("Eroare eveniment HA: %s", e)


def save_image(dev: str, b64: str, prefix: str = "") -> str | None:
    if not b64:
        return None
    try:
        img = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except (binascii.Error, ValueError) as e:
        LOG.warning("base64 invalid: %s", e)
        return None
    d = WWW / dev
    d.mkdir(parents=True, exist_ok=True)
    name = f"{prefix}{time.strftime('%Y%m%d_%H%M%S')}.jpg"
    (d / name).write_bytes(img)
    (d / "last.jpg").write_bytes(img)
    files = sorted(p for p in d.glob("*2*.jpg") if p.name != "last.jpg")
    for p in files[:-50]:
        p.unlink(missing_ok=True)
    return f"/local/naxclow/{dev}/{name}"


def handle_local(path: str, f: dict) -> dict | None:
    """Prelucrare locală (poze + eveniment). Întoarce datele evenimentului sau None."""
    dev = f.get("devicesCode") or f.get("deviceCode")
    if not dev:
        return None
    if path.endswith("/v6SendAlert"):
        kind, prefix = "alert", ""
    elif "SendBase64IMG" in path:
        kind, prefix = "ring_image", "ring_"
    else:
        return None
    url = save_image(dev, f.get("base64", ""), prefix)
    ev = {
        "device": dev,
        "kind": kind,
        "record_type": f.get("recordType"),
        "type": f.get("type"),
        "battery_mv": int(f["battery"]) if f.get("battery", "").isdigit() else None,
        "image": url,
        "fields": {k: v for k, v in f.items() if k not in ("base64",) + SECRET_KEYS},
    }
    LOG.info("EVENIMENT %s %s type=%s battery=%s img=%s", kind, dev, ev["type"], ev["battery_mv"], url)
    asyncio.create_task(fire_event(ev))
    return ev


def local_alert_response(dev: str) -> dict:
    return {
        "isLock": False,
        "random": secrets.randbelow(10**9),
        "eventId": secrets.token_hex(16),
        "code": 200,
        "data": SETTINGS,
        "updateUrl": None,
        "conf": {"tcpPort": TCP_PORT, "uid": dev, "domain": "home.naxclow.com",
                 "host": local_ip(), "pwd": secrets.token_hex(4)},
        "id": secrets.token_hex(16),
        "message": "操作成功",
        "version": None,
    }


async def http_any(request: web.Request):
    raw = await request.read()
    path = request.path
    f = parse_form(raw) if b"=" in raw[:200] else {}
    handle_local(path, f)
    summary = {k: (v[:20] + "…" if k == "base64" else v) for k, v in f.items()} if f else raw[:300]
    journal(f"HTTP> {request.method} {request.path_qs} {redact(summary) if f else summary!r}")

    if MODE == "proxy":
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("content-length", "transfer-encoding", "connection")}
        try:
            async with ClientSession(timeout=ClientTimeout(total=15)) as s:
                async with s.request(request.method, f"http://{UPSTREAM_HTTP}{request.path_qs}",
                                     data=raw, headers=headers) as r:
                    body = await r.read()
                    ctype = r.headers.get("Content-Type", "application/json")
                    status = r.status
        except Exception as e:  # noqa: BLE001
            LOG.error("Upstream HTTP eșuat (%s), răspund local", e)
            journal(f"HTTP! upstream eroare {e}")
            return local_reply(path, f)
        try:
            js = json.loads(body)
            conf = js.get("conf") if isinstance(js, dict) else None
            if isinstance(conf, dict) and conf.get("host"):
                REAL_TCP[str(conf.get("uid"))] = (conf["host"], int(conf.get("tcpPort", 29838)))
                conf["host"] = local_ip()
                conf["tcpPort"] = TCP_PORT
                body = jdump(js).encode()
            journal(f"HTTP< {status} {jdump(redact(js))[:2000]}")
        except ValueError:
            journal(f"HTTP< {status} {body[:500]!r}")
        return web.Response(body=body, status=status, content_type=ctype.split(";")[0])

    return local_reply(path, f)


def local_reply(path: str, f: dict):
    dev = f.get("devicesCode") or f.get("deviceCode") or "unknown"
    if path.endswith("/v6SendAlert"):
        return web.Response(text=jdump(local_alert_response(dev)), content_type="application/json")
    if "SendBase64IMG" in path or path == "/favicon.ico":
        return web.Response(text=jdump({"code": 200, "message": "操作成功", "data": None}),
                            content_type="application/json")
    LOG.warning("Endpoint fără răspuns cunoscut: %s", path)
    return web.Response(text=jdump({"code": 200, "message": "操作成功", "data": None}),
                        content_type="application/json")


# ---------------- TCP ----------------

class FrameLogger:
    """Desparte fluxul în cadre (header 20 B + payload) și le jurnalizează."""

    def __init__(self, tag: str, fh):
        self.tag, self.fh, self.buf = tag, fh, b""

    def feed(self, data: bytes):
        if self.fh:
            self.fh.write(struct.pack("<cI", self.tag[0].encode(), len(data)) + data)
            self.fh.flush()
        self.buf += data
        while len(self.buf) >= 20:
            ln = struct.unpack_from("<I", self.buf)[0]
            if ln > 2_000_000:  # nu pare cadru -> logăm brut și renunțăm la parsare
                journal(f"TCP{self.tag} RAW {len(self.buf)}B {self.buf[:64].hex(' ')}")
                self.buf = b""
                return
            if len(self.buf) < 20 + ln:
                return
            hdr, payload = self.buf[:20], self.buf[20:20 + ln]
            self.buf = self.buf[20 + ln:]
            extra = hdr[4:].hex() if any(hdr[4:]) else ""
            if payload[:1] == b"{":
                try:
                    txt = jdump(redact(json.loads(payload)))
                except ValueError:
                    txt = payload[:300].decode("latin1")
                journal(f"TCP{self.tag} {ln}B {extra} {txt[:1500]}")
                LOG.info("TCP%s %s", self.tag, txt[:300])
            else:
                journal(f"TCP{self.tag} {ln}B {extra} BIN {payload[:48].hex(' ')}")


async def pipe(reader, writer, logger: FrameLogger):
    try:
        while data := await reader.read(65536):
            logger.feed(data)
            writer.write(data)
            await writer.drain()
    except Exception as e:  # noqa: BLE001
        LOG.debug("pipe %s: %s", logger.tag, e)
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    if MODE == "local":
        journal(f"TCP+ {peer} mod=local")
        await HUB.handle_tcp(reader, writer)
        return
    SHARE.mkdir(parents=True, exist_ok=True)
    fn = SHARE / f"tcp_{time.strftime('%Y%m%d_%H%M%S')}_{peer[0]}.bin"
    fh = open(fn, "wb") if TCP_CAPTURE else None
    LOG.info("TCP conectat %s (mod %s)", peer, MODE)
    journal(f"TCP+ {peer} mod={MODE}")
    up = FrameLogger(">", fh)    # sonerie -> cloud
    down = FrameLogger("<", fh)  # cloud -> sonerie
    try:
        if MODE == "proxy":
            host, port = (next(iter(REAL_TCP.values()), None)
                          or (UPSTREAM_TCP.split(":")[0], int(UPSTREAM_TCP.split(":")[1])))
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            except Exception as e:  # noqa: BLE001
                LOG.error("Nu mă pot conecta la %s:%s: %s", host, port, e)
                return
            journal(f"TCP~ upstream {host}:{port}")
            await asyncio.gather(pipe(reader, uw, up), pipe(ur, writer, down))
        else:
            while data := await reader.read(65536):
                up.feed(data)
    finally:
        if fh:
            fh.close()
        LOG.info("TCP închis %s", peer)
        journal(f"TCP- {peer}")
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------- UDP (probabil media) ----------------

class UdpUpstream(asyncio.DatagramProtocol):
    """Socket nelegat de o adresă: primește de la server ȘI de la peer-ul P2P (telefon)."""

    def __init__(self, front, client, server):
        self.front, self.client, self.server, self.transport = front, client, server, None
        self.peers: set = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        tag = "<" if addr == self.server else "P"
        if tag == "P" and addr not in self.peers:
            self.peers.add(addr)
            journal(f"UDP peer nou {addr[0]}:{addr[1]} -> sonerie {self.client}")
        self.front.stat(tag, self.client, data, src=addr)
        self.front.transport.sendto(data, self.client)


class UdpFront(asyncio.DatagramProtocol):
    """Primește UDP de la sonerie; în proxy îl trimite la relay-ul real și întoarce răspunsurile."""

    def __init__(self):
        self.transport = None
        self.ups: dict[tuple, UdpUpstream] = {}
        self.counters: dict[tuple, list] = {}
        self.fh = None

    def connection_made(self, transport):
        self.transport = transport

    def stat(self, tag, client, data, src=None):
        key = (tag, client)
        c = self.counters.setdefault(key, [0, 0, time.time()])
        c[0] += 1
        c[1] += len(data)
        if c[0] <= (40 if tag == "P" else 5):
            who = f" de la {src[0]}:{src[1]}" if src else ""
            journal(f"UDP{tag} {client[0]}:{client[1]}{who} {len(data)}B {data[:64].hex(' ')}")
        if TCP_CAPTURE:
            if self.fh is None:
                SHARE.mkdir(parents=True, exist_ok=True)
                self.fh = open(SHARE / f"udp_{time.strftime('%Y%m%d_%H%M%S')}.bin", "wb")
            self.fh.write(struct.pack("<cdI", tag.encode(), time.time(), len(data)) + data)
            self.fh.flush()

    def datagram_received(self, data, addr):
        if MODE == "local":
            HUB.handle_udp(data, addr)
            return
        self.stat(">", addr, data)
        up = self.ups.get(addr)
        if up is None:
            host, port = (next(iter(REAL_TCP.values()), None)
                          or (UPSTREAM_TCP.split(":")[0], int(UPSTREAM_TCP.split(":")[1])))
            loop = asyncio.get_running_loop()
            up = UdpUpstream(self, addr, (host, port))
            self.ups[addr] = up
            asyncio.ensure_future(loop.create_datagram_endpoint(lambda: up, local_addr=("0.0.0.0", 0)))
            journal(f"UDP~ {addr} -> upstream {host}:{port}")
            # primul pachet îl trimitem după ce endpoint-ul e gata
            async def later():
                for _ in range(50):
                    if up.transport:
                        up.transport.sendto(data, up.server)
                        return
                    await asyncio.sleep(0.02)
            asyncio.ensure_future(later())
            return
        if up.transport:
            up.transport.sendto(data, up.server)


async def udp_summary(front: UdpFront):
    while True:
        await asyncio.sleep(10)
        for (tag, client), c in list(front.counters.items()):
            if c[0]:
                journal(f"UDP{tag} {client[0]} rezumat: {c[0]} pachete, {c[1]} B în ultimele ~10 s")
                LOG.info("UDP%s %s: %d pachete / %d B", tag, client[0], c[0], c[1])
            front.counters[(tag, client)] = [0, 0, time.time()]


async def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "info").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    global HUB
    HUB = LocalHub(SHARE, journal, fire_event, AUTO_STREAM, MAX_STREAM)
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_routes(HUB.routes(web))
    app.router.add_route("*", "/{tail:.*}", http_any)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", HTTP_PORT).start()
    LOG.info("Mod %s | HTTP :%d | IP anunțat: %s | upstream HTTP %s TCP %s",
             MODE, HTTP_PORT, local_ip(), UPSTREAM_HTTP, UPSTREAM_TCP)
    srv = await asyncio.start_server(tcp_handler, "0.0.0.0", TCP_PORT)
    LOG.info("TCP pe :%d (capture=%s)", TCP_PORT, TCP_CAPTURE)
    front = UdpFront()
    await asyncio.get_running_loop().create_datagram_endpoint(lambda: front, local_addr=("0.0.0.0", TCP_PORT))
    HUB.udp = front.transport
    asyncio.ensure_future(udp_summary(front))
    LOG.info("UDP pe :%d", TCP_PORT)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
