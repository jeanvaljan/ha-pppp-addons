"""Emulare locală a serverului relay Naxclow (TCP control + UDP media).

Protocol (reverse engineered din trafic real):
  Cadru TCP/UDP: header 20 B + payload
    TCP server->dev : <I len><H cmd> ff 00 ff*8 00*4
    UDP sesiune     : <I len><H typ><B flag><B 1> forwardId[8] <I seq>
  TCP: dev code 100 (login) -> code 101; cmd 0x65 heartbeat -> 0x66
       server code 31 {forwardId} -> deschide relay; code 53 status 1/0 start/stop
  UDP: dev code 20 -> code 21 {ip,port}; dev tip 100 keepalive
       server code 50 -> dev code 51; server code 54 + tip 101 (ping) -> dev 55 + 102
       dev tip 1 = fragment JPEG (flag fa=start, fb=mijloc, fc=sfârșit), tip 4 = audio A-law
       server tip 605 = ACK selectiv: listă u32 seq
"""
import asyncio
import json
import logging
import os
import secrets
import string
import struct
import time
from collections import deque
from pathlib import Path

LOG = logging.getLogger("naxclow.local")

SRV_TAIL = b"\xff\x00" + b"\xff" * 8 + b"\x00" * 4


def tcp_frame(payload: bytes, cmd: int = 0) -> bytes:
    return struct.pack("<IH", len(payload), cmd) + SRV_TAIL + payload


def udp_srv_frame(payload: bytes) -> bytes:
    return struct.pack("<IH", len(payload), 0) + SRV_TAIL + payload


def udp_sess_frame(fid: bytes, payload: bytes = b"", typ: int = 0) -> bytes:
    return struct.pack("<IHBB", len(payload), typ, 0, 1) + fid + b"\x00\x00\x00\x00" + payload


def jb(o) -> bytes:
    return json.dumps(o, separators=(",", ":")).encode()


class Device:
    def __init__(self, uid: str):
        self.uid = uid
        self.token = ""
        self.writer: asyncio.StreamWriter | None = None
        self.ip: str | None = None
        self.udp_addr: tuple | None = None
        self.udp_ready = asyncio.Event()
        # sesiune stream
        self.fid: bytes | None = None
        self.cli_id = ""
        self.got51 = asyncio.Event()
        self.streaming = False
        self.stream_task: asyncio.Task | None = None
        self.stop_at = 0.0
        self.acks: deque = deque(maxlen=18)
        self.ack_pending = False
        self.seen: deque = deque(maxlen=4000)
        self.seen_set: set = set()
        self.cur: list | None = None
        self.last_jpeg: bytes | None = None
        self.last_ts = 0.0
        self.subs: set[asyncio.Queue] = set()
        self.frames = 0
        self.clip = None
        self.clip_path: Path | None = None
        self.audio = None

    @property
    def online(self):
        return self.writer is not None and not self.writer.is_closing()


class LocalHub:
    def __init__(self, share: Path, journal, fire_event, auto_stream: int, max_stream: int):
        self.devs: dict[str, Device] = {}
        self.by_ip: dict[str, Device] = {}
        self.share = share
        self.journal = journal
        self.fire_event = fire_event
        self.auto_stream = auto_stream
        self.max_stream = max_stream
        self.udp = None  # transport
        self.cli_port = 29838  # portul „client" anunțat în code 11 = socket-ul nostru UDP
        self.dbg: dict = {}

    # ---------- TCP ----------
    async def handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        buf = b""
        dev: Device | None = None
        try:
            while data := await reader.read(65536):
                buf += data
                while len(buf) >= 20:
                    ln = struct.unpack_from("<I", buf)[0]
                    if len(buf) < 20 + ln:
                        break
                    cmd = struct.unpack_from("<H", buf, 4)[0]
                    payload = buf[20:20 + ln]
                    buf = buf[20 + ln:]
                    if cmd == 0x65:  # heartbeat
                        writer.write(tcp_frame(b"", 0x66))
                        continue
                    if cmd == 0x64 or not payload:
                        continue
                    try:
                        js = json.loads(payload)
                    except ValueError:
                        self.journal(f"L-TCP> non-json {payload[:60]!r}")
                        continue
                    code = js.get("code")
                    if code == 100:
                        dev = self.devs.setdefault(js["uid"], Device(js["uid"]))
                        dev.token, dev.writer, dev.ip = js.get("token", ""), writer, peer[0]
                        self.by_ip[peer[0]] = dev
                        writer.write(tcp_frame(jb({"code": 101, "status": 200})))
                        LOG.info("Sonerie %s logată (%s)", dev.uid, peer[0])
                        self.journal(f"L-TCP login {dev.uid} {peer}")
                        if self.auto_stream > 0:
                            asyncio.ensure_future(self.start_stream(dev, self.auto_stream, reason="auto"))
                    else:
                        self.journal(f"L-TCP> {jb(js).decode()[:300]}")
                        if code == 12 and dev and js.get("status") == 200 and js.get("devNatIp"):
                            dev.udp_addr = (js["devNatIp"], int(js["devNatPort"]))
                            dev.udp_ready.set()
                await writer.drain()
        except Exception as e:  # noqa: BLE001
            LOG.debug("TCP local %s: %s", peer, e)
        finally:
            if dev and dev.writer is writer:
                dev.writer = None
                dev.udp_ready.clear()
                LOG.info("Sonerie %s deconectată", dev.uid)
                self.journal(f"L-TCP închis {dev.uid}")
            writer.close()

    def tcp_send(self, dev: Device, obj):
        if dev.online:
            dev.writer.write(tcp_frame(jb(obj)))
            self.journal(f"L-TCP< {jb(obj).decode()}")

    # ---------- UDP ----------
    def handle_udp(self, data: bytes, addr: tuple):
        if len(data) < 20:
            self.journal(f"L-UDP> scurt {addr} {data.hex(' ')}")
            return
        ln, typ, flag, b7 = struct.unpack_from("<IHBB", data)
        seq = struct.unpack_from("<I", data, 16)[0]
        payload = data[20:20 + ln]
        k = (addr, typ)
        c = self.dbg.setdefault(k, [0, 0])
        c[0] += 1
        c[1] += len(data)
        if c[0] <= 6:
            self.journal(f"L-UDP> {addr[0]}:{addr[1]} typ={typ} hdr={data[:20].hex()} {payload[:120]!r}")
        dev = self.by_ip.get(addr[0])
        if typ == 0 and payload[:1] == b"{":
            try:
                js = json.loads(payload)
            except ValueError:
                return
            code = js.get("code")
            if code == 20:
                self.udp.sendto(udp_srv_frame(jb({"code": 21, "ip": addr[0], "port": addr[1]})), addr)
                if dev:
                    dev.udp_addr = addr
                    dev.udp_ready.set()
            elif code == 51 and dev:
                dev.got51.set()
            elif code == 55:
                pass
            else:
                self.journal(f"L-UDP> {payload[:200]!r}")
            return
        if dev is None:
            return
        if typ == 100:
            dev.udp_addr = addr
            dev.udp_ready.set()
            return
        if typ in (1, 4) and dev.fid:
            self.ack(dev, seq)
            if seq in dev.seen_set:
                return
            if len(dev.seen) == dev.seen.maxlen:
                dev.seen_set.discard(dev.seen[0])
            dev.seen.append(seq)
            dev.seen_set.add(seq)
            if typ == 1:
                self.video(dev, flag, payload)
            elif dev.audio:
                dev.audio.write(payload)

    async def dbg_summary(self):
        while True:
            await asyncio.sleep(10)
            for (addr, typ), c in list(self.dbg.items()):
                if c[0] > 6:
                    self.journal(f"L-UDP rezumat {addr[0]}:{addr[1]} typ={typ}: {c[0]} pachete, {c[1]} B")
            self.dbg.clear()

    def ack(self, dev: Device, seq: int):
        dev.acks.append(seq)
        if not dev.ack_pending:
            dev.ack_pending = True
            asyncio.get_running_loop().call_later(0.02, self.flush_ack, dev)

    def flush_ack(self, dev: Device):
        dev.ack_pending = False
        if dev.udp_addr and dev.fid and dev.acks:
            pl = b"".join(struct.pack("<I", s) for s in dev.acks)
            self.udp.sendto(udp_sess_frame(dev.fid, pl, 605), dev.udp_addr)

    def video(self, dev: Device, flag: int, payload: bytes):
        if flag == 0xFA:
            dev.cur = [payload]
        elif dev.cur is not None:
            dev.cur.append(payload)
            if flag == 0xFC:
                jpg = b"".join(dev.cur)
                dev.cur = None
                end = jpg.rfind(b"\xff\xd9")
                if jpg[:2] != b"\xff\xd8" or end < 0:
                    return
                jpg = jpg[:end + 2]
                dev.last_jpeg, dev.last_ts = jpg, time.time()
                dev.frames += 1
                if dev.clip:
                    dev.clip.write(jpg)
                for q in list(dev.subs):
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    q.put_nowait(jpg)

    # ---------- sesiune stream ----------
    async def start_stream(self, dev: Device, seconds: int, reason: str = "manual") -> bool:
        seconds = min(seconds, self.max_stream)
        if dev.streaming:
            dev.stop_at = max(dev.stop_at, time.time() + seconds)
            return True
        if not dev.online:
            return False
        dev.streaming = True
        dev.stop_at = time.time() + seconds
        dev.stream_task = asyncio.ensure_future(self._session(dev, reason))
        return True

    async def _session(self, dev: Device, reason: str):
        fid = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        dev.fid, dev.cli_id = fid.encode(), secrets.token_hex(16)
        dev.got51.clear()
        dev.frames, dev.cur = 0, None
        dev.acks.clear()
        dev.seen.clear()
        dev.seen_set.clear()
        clips = self.share / "clips"
        clips.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        dev.clip_path = clips / f"{dev.uid}_{ts}.mjpeg"
        dev.clip = open(dev.clip_path, "wb")
        dev.audio = open(clips / f"{dev.uid}_{ts}.alaw", "wb")
        LOG.info("%s: pornesc stream (%s, fid %s)", dev.uid, reason, fid)
        try:
            if not await self._wake_udp(dev):
                LOG.warning("%s: soneria nu s-a înregistrat pe UDP, renunț", dev.uid)
                return
            self.tcp_send(dev, {"code": 31, "status": 200, "target": dev.cli_id, "forwardId": fid})
            hello = jb({"code": 50, "cliToken": secrets.token_hex(4), "devTarget": dev.uid,
                        "cliId": dev.cli_id, "devToken": dev.token})
            for _ in range(40):
                self.udp.sendto(udp_sess_frame(dev.fid, hello), dev.udp_addr)
                try:
                    await asyncio.wait_for(dev.got51.wait(), 0.15)
                    break
                except asyncio.TimeoutError:
                    pass
            if not dev.got51.is_set():
                LOG.warning("%s: fără code 51, renunț", dev.uid)
                return
            self.tcp_send(dev, {"code": 53, "target": dev.cli_id, "status": 1})
            while dev.online and time.time() < dev.stop_at:
                self.udp.sendto(udp_sess_frame(dev.fid, jb({"timerStamp": str(int(time.time() * 1000)), "code": 54})),
                                dev.udp_addr)
                self.udp.sendto(udp_sess_frame(dev.fid, b"", 101), dev.udp_addr)
                await asyncio.sleep(2)
            self.tcp_send(dev, {"code": 53, "target": dev.cli_id, "status": 0})
        finally:
            dev.streaming = False
            dev.fid = None
            for f in (dev.clip, dev.audio):
                if f:
                    f.close()
            dev.clip = dev.audio = None
            LOG.info("%s: stream oprit, %d cadre", dev.uid, dev.frames)
            self.journal(f"L-STREAM {dev.uid} {reason} {dev.frames} cadre -> {dev.clip_path.name}")
            if dev.frames == 0:
                dev.clip_path.unlink(missing_ok=True)
                (dev.clip_path.with_suffix(".alaw")).unlink(missing_ok=True)
            else:
                await self.fire_event({"device": dev.uid, "kind": "clip", "reason": reason,
                                       "frames": dev.frames, "clip": str(dev.clip_path)})
            self._prune(clips)

    async def _wake_udp(self, dev: Device) -> bool:
        """code 11 (cerere de conectare client) face soneria să se înregistreze pe UDP."""
        if dev.udp_ready.is_set():
            return True
        me = self.my_ip(dev)
        for attempt in range(4):
            self.tcp_send(dev, {"code": 11, "cliTarget": dev.cli_id, "cliToken": secrets.token_hex(4),
                                "cliIp": me, "cliPort": self.cli_port, "cliNatIp": me,
                                "cliNatPort": self.cli_port})
            try:
                await asyncio.wait_for(dev.udp_ready.wait(), 3.5)
                return True
            except asyncio.TimeoutError:
                if not dev.online:
                    return False
        return dev.udp_ready.is_set()

    def my_ip(self, dev: Device) -> str:
        try:
            return dev.writer.get_extra_info("sockname")[0]
        except Exception:  # noqa: BLE001
            return "0.0.0.0"

    @staticmethod
    def _prune(clips: Path, keep: int = 30):
        files = sorted(clips.glob("*.mjpeg"))
        for p in files[:-keep]:
            p.unlink(missing_ok=True)
            p.with_suffix(".alaw").unlink(missing_ok=True)

    # ---------- HTTP pentru HA / go2rtc ----------
    def routes(self, web):
        hub = self

        def get_dev(request):
            uid = request.match_info["uid"]
            if uid == "any" and hub.devs:
                return next(iter(hub.devs.values()))
            return hub.devs.get(uid)

        async def snapshot(request):
            dev = get_dev(request)
            if not dev or not dev.last_jpeg:
                return web.Response(status=404, text="no frame")
            return web.Response(body=dev.last_jpeg, content_type="image/jpeg")

        async def start(request):
            dev = get_dev(request)
            secs = int(request.query.get("seconds", hub.max_stream))
            ok = bool(dev) and await hub.start_stream(dev, secs, reason="http")
            return web.json_response({"ok": ok, "online": bool(dev and dev.online)})

        async def status(request):
            return web.json_response({u: {"online": d.online, "streaming": d.streaming, "frames": d.frames,
                                          "last_frame_age": round(time.time() - d.last_ts, 1) if d.last_ts else None}
                                      for u, d in hub.devs.items()})

        async def mjpeg(request):
            dev = get_dev(request)
            if not dev:
                return web.Response(status=404, text="unknown device")
            if not dev.streaming and not await hub.start_stream(dev, hub.max_stream, reason="viewer"):
                return web.Response(status=503, text="device asleep")
            q: asyncio.Queue = asyncio.Queue(maxsize=3)
            dev.subs.add(q)
            resp = web.StreamResponse(headers={"Content-Type": "multipart/x-mixed-replace; boundary=frame"})
            await resp.prepare(request)
            try:
                while dev.streaming or not q.empty():
                    try:
                        jpg = await asyncio.wait_for(q.get(), 5)
                    except asyncio.TimeoutError:
                        if not dev.streaming:
                            break
                        continue
                    await resp.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                     + str(len(jpg)).encode() + b"\r\n\r\n" + jpg + b"\r\n")
            except (ConnectionResetError, asyncio.CancelledError):
                pass
            finally:
                dev.subs.discard(q)
            return resp

        return [
            web.get("/cam/status", status),
            web.get("/cam/{uid}/snapshot.jpg", snapshot),
            web.get("/cam/{uid}/stream.mjpg", mjpeg),
            web.get("/cam/{uid}/start", start),
        ]
