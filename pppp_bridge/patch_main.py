"""Patch aiopppp 0.2.3 __main__.py:
- nu mai creează sesiune duplicată la fiecare redescoperire (cauza crash-ului)
- o sesiune căzută e ștearsă și refăcută la următoarea descoperire, fără să oprească serverul
- adaugă opțiunea --port pentru serverul web
"""
import pathlib
import sys

import aiopppp

p = pathlib.Path(aiopppp.__file__).parent / "__main__.py"
s = p.read_text()
if "_drop_session" in s:
    print("already patched")
    sys.exit(0)

start = s.index("def get_new_device_fut")
end = s.index("def main():")
new = '''def get_new_device_fut():
    return new_device_fut


def _poke():
    fut = get_new_device_fut()
    if fut is not None and not fut.done():
        fut.set_result(None)


def on_device_found(device, login, password):
    dev_id = device.dev_id.dev_id
    if dev_id in SESSIONS:
        return
    session = make_session(device, on_device_lost=on_device_lost, login=login, password=password)
    SESSIONS[dev_id] = session
    session.start()
    tasks[dev_id] = session.running_tasks()
    _poke()


def on_device_lost(device):
    logger.warning('Device %s lost', device.dev_id)
    SESSIONS.pop(device.dev_id.dev_id, None)
    tasks.pop(device.dev_id.dev_id, None)
    _poke()


def _drop_session(dev_id, reason):
    logger.warning('Session %s ended (%r); reconnect on next discovery', dev_id, reason)
    s = SESSIONS.pop(dev_id, None)
    tasks.pop(dev_id, None)
    if s:
        try:
            s.stop()
        except Exception:
            pass


async def amain(remote_addr, local_port, username, password, http_port=4000):
    global discovery
    global new_device_fut
    discovery = Discovery(remote_addr=remote_addr)

    discovery_task = asyncio.create_task(discovery.discover(lambda d: on_device_found(d, username, password)))
    webserver_task = asyncio.create_task(start_web_server(port=http_port))
    core = {discovery_task, webserver_task}
    try:
        while True:
            new_device_fut = asyncio.Future()
            dev_tasks = set(t for task_list in tasks.values() for t in task_list)
            done, pending = await asyncio.wait(
                [*core, new_device_fut, *dev_tasks],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if done & core:
                await asyncio.gather(*(done & core))
                break
            for t in done:
                if t is new_device_fut:
                    continue
                exc = None if t.cancelled() else t.exception()
                for dev_id, tl in list(tasks.items()):
                    if t in tl:
                        _drop_session(dev_id, exc)
    finally:
        for dev_id, session in list(SESSIONS.items()):
            try:
                session.stop()
            except Exception:
                pass
        SESSIONS.clear()


'''
s = s[:start] + new + s[end:]

# --port
s = s.replace(
    "    args = parser.parse_args()",
    "    parser.add_argument('--port', type=int, default=4000, help='HTTP port')\n\n    args = parser.parse_args()",
)
s = s.replace(
    "        password=args.password,\n    ))",
    "        password=args.password,\n        http_port=args.port,\n    ))",
)
p.write_text(s)
print("patched", p)
