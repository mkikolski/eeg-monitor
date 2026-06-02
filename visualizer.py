import asyncio
import json
import os
import time
import threading
import http.server
from pathlib import Path

# Python 3.8+ doesn't search cwd for DLLs; register the project root so
# hidapi.dll placed next to visualizer.py is found on Windows.
if hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(str(Path(__file__).resolve().parent))

import hid
from Crypto.Cipher import AES
from loguru import logger
import websockets

HTTP_PORT = 2139
WS_PORT = 2140
EMOTIV_VENDOR_ID = 4660  # 0x1234
MODEL = 6
RETRY_INTERVAL = 2
FALLBACK_SERIAL = "EX0000B2C001205E"

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1',
    'O2', 'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4',
]

# All connected browser websocket clients
_clients: set = set()
_device_connected: bool = False


def generate_aes_key(serial: str) -> bytes:
    if not serial or len(serial) < 4:
        raise ValueError("Serial number too short.")
    s = serial.encode()
    return bytes([
        s[-1], s[-2], s[-4], s[-4], s[-2], s[-1], s[-2], s[-4],
        s[-1], s[-4], s[-3], s[-2], s[-1], s[-2], s[-2], s[-3],
    ])


def decode_packet(data: bytes, key: bytes) -> list[float]:
    """XOR, decrypt, parse bytes 2-15 and 18-31, convert to µV, reorder channels."""
    xored = bytes(b ^ 0x55 for b in data)
    dec = AES.new(key, AES.MODE_ECB).decrypt(xored)

    def to_uv(hi: int, lo: int) -> float:
        return ((hi * 0.128205128205129) + 4201.02564096001) + ((lo - 128) * 32.82051289)

    raw = [to_uv(dec[i], dec[i + 1]) for i in range(2, 16, 2)]   # bytes 2-15  → 7 values
    raw += [to_uv(dec[i], dec[i + 1]) for i in range(18, 32, 2)] # bytes 18-31 → 7 values
    # raw order: F3, F7, FC5, T7, P7, O1, O2, P8, T8, FC6, F8, AF4, F4, AF3
    # swap to: AF3, F7, F3, FC5, T7, P7, O1, O2, P8, T8, FC6, F4, F8, AF4
    raw[0], raw[2] = raw[2], raw[0]   # AF3 ↔ F3
    raw[13], raw[11] = raw[11], raw[13]  # AF4 ↔ F4
    raw[1], raw[3] = raw[3], raw[1]   # F7 ↔ FC5
    raw[10], raw[12] = raw[12], raw[10]  # FC6 ↔ F8
    return raw


def _pick_interface(interfaces: list) -> dict:
    """Prefer vendor-defined usage pages (0xFF00+) — that's where EEG data lives."""
    vendor = [d for d in interfaces if d.get('usage_page', 0) >= 0xFF00]
    chosen = vendor[0] if vendor else interfaces[0]
    if len(interfaces) > 1:
        logger.debug(
            "Picked interface: path={} usage_page=0x{:04x} (from {} total)",
            chosen['path'], chosen.get('usage_page', 0), len(interfaces),
        )
    return chosen


def hid_reader(
    data_queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            all_interfaces = [d for d in hid.enumerate() if d['vendor_id'] == EMOTIV_VENDOR_ID]
            if all_interfaces:
                logger.debug(
                    "All Emotiv HID interfaces ({}):\n{}",
                    len(all_interfaces),
                    "\n".join(
                        f"  path={d['path']}  usage_page=0x{d.get('usage_page',0):04x}"
                        f"  usage=0x{d.get('usage',0):04x}  product={d.get('product_string','')!r}"
                        for d in all_interfaces
                    ),
                )
            if not all_interfaces:
                all_vids = sorted({d['vendor_id'] for d in hid.enumerate()})
                logger.warning(
                    "Emotiv device not found (visible VIDs: {}) — retrying in {}s...",
                    [hex(v) for v in all_vids],
                    RETRY_INTERVAL,
                )
                time.sleep(RETRY_INTERVAL)
                continue

            device_info = _pick_interface(all_interfaces)
            serial = device_info.get('serial_number') or FALLBACK_SERIAL
            if len(serial) < 4:
                serial = FALLBACK_SERIAL
            logger.info(
                "Found: {} (serial: {}, path: {})",
                device_info.get('product_string', ''),
                serial,
                device_info['path'],
            )
            key = generate_aes_key(serial)
            logger.debug("AES key: {}", key.hex())

            with hid.Device(path=device_info['path']) as dev:
                logger.info("Connected — waiting for packets (usage_page=0x{:04x})", device_info.get('usage_page', 0))
                loop.call_soon_threadsafe(
                    data_queue.put_nowait, {"event": "device_connected"}
                )
                pkt_count = 0
                silent_ticks = 0

                while not stop_event.is_set():
                    raw = dev.read(32, timeout_ms=500)
                    if not raw:
                        silent_ticks += 1
                        if silent_ticks % 10 == 0:
                            logger.warning("No data from device for {}s — is it streaming?", silent_ticks // 2)
                        continue
                    silent_ticks = 0

                    if pkt_count < 3:
                        logger.debug("Packet #{} raw: {}", pkt_count, bytes(raw).hex())

                    try:
                        channels = decode_packet(bytes(raw), key)
                    except Exception as e:
                        logger.debug("Decode error on packet #{}: {}", pkt_count, e)
                        pkt_count += 1
                        continue

                    if pkt_count < 3:
                        logger.debug("Packet #{} decoded (µV): {}", pkt_count, [f'{v:.1f}' for v in channels])

                    pkt_count += 1
                    loop.call_soon_threadsafe(data_queue.put_nowait, channels)

            loop.call_soon_threadsafe(
                data_queue.put_nowait, {"event": "device_disconnected"}
            )
            logger.warning("Device closed — retrying in {}s...", RETRY_INTERVAL)
            time.sleep(RETRY_INTERVAL)

        except Exception as exc:
            loop.call_soon_threadsafe(
                data_queue.put_nowait, {"event": "device_disconnected"}
            )
            logger.error("HID error: {} — retrying in {}s...", exc, RETRY_INTERVAL)
            time.sleep(RETRY_INTERVAL)


async def ws_handler(websocket) -> None:
    _clients.add(websocket)
    logger.info("Browser connected ({})", websocket.remote_address)
    try:
        # Tell the new client the current device state immediately
        event = "device_connected" if _device_connected else "device_disconnected"
        await websocket.send(json.dumps({"event": event}))
        await websocket.wait_closed()
    finally:
        _clients.discard(websocket)
        logger.info("Browser disconnected")


async def broadcast_loop(data_queue: asyncio.Queue) -> None:
    global _device_connected
    while True:
        item = await data_queue.get()
        if isinstance(item, dict):
            if item.get("event") == "device_connected":
                _device_connected = True
            elif item.get("event") == "device_disconnected":
                _device_connected = False
        if not _clients:
            continue
        if isinstance(item, dict):
            msg = json.dumps(item)
        else:
            msg = json.dumps({"names": CHANNEL_NAMES, "channels": item})
        dead = set()
        for ws in list(_clients):
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        _clients.difference_update(dead)


def _start_http_server(port: int) -> None:
    dashboard = Path(__file__).parent / "dashboard.html"

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.rstrip('/') in ('', '/dashboard.html'):
                content = dashboard.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass  # suppress per-request noise

    http.server.HTTPServer(('0.0.0.0', port), _Handler).serve_forever()


async def main() -> None:
    logger.remove()
    logger.add(lambda msg: print(msg, end=""), level="DEBUG", colorize=True)

    data_queue: asyncio.Queue = asyncio.Queue()
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()

    threading.Thread(
        target=hid_reader, args=(data_queue, loop, stop_event), daemon=True
    ).start()

    threading.Thread(
        target=_start_http_server, args=(HTTP_PORT,), daemon=True
    ).start()

    logger.info("Dashboard  →  http://localhost:{}", HTTP_PORT)
    logger.info("WebSocket  →  ws://localhost:{}", WS_PORT)

    async with websockets.serve(ws_handler, "0.0.0.0", WS_PORT):
        await broadcast_loop(data_queue)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down.")
