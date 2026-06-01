import asyncio
import json
import time
import threading
import http.server
from pathlib import Path

import hid
from Crypto.Cipher import AES
from loguru import logger
import websockets

HTTP_PORT = 2139
WS_PORT = 2140
EMOTIV_VENDOR_ID = 4660  # 0x1234
MODEL = 6
RETRY_INTERVAL = 2
READ_TIMEOUT_MS = 100  # milliseconds, kwarg is 'timeout' not 'timeout_ms'
FALLBACK_SERIAL = "EX0000B2C001205E"

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1', 'O2',
    'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4', 'GYRO_X', 'GYRO_Y',
]

# All connected browser websocket clients
_clients: set = set()


def generate_aes_key(serial_number: str, model: int) -> str:
    if not serial_number or len(serial_number) < 4:
        raise ValueError("Invalid serial number length.")
    if model == 2:
        k = [serial_number[-1], '\0', serial_number[-2], 'T',
             serial_number[-3], '\x10', serial_number[-4], 'B',
             serial_number[-1], '\0', serial_number[-2], 'H',
             serial_number[-3], '\0', serial_number[-4], 'P']
    else:
        k = [serial_number[-1], serial_number[-2], serial_number[-3],
             serial_number[-4], 'A', 'B', 'C', 'D', 'E', 'F', 'G',
             'H', 'I', 'J', 'K', 'L']
    key = ''.join(k)
    if len(key) not in (16, 24, 32):
        key = key.ljust(16, '\0')[:16]
    return key


def hid_reader(
    data_queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            device_info = next(
                (d for d in hid.enumerate() if d['vendor_id'] == EMOTIV_VENDOR_ID),
                None,
            )
            if device_info is None:
                logger.warning("Emotiv device not found — retrying in {}s...", RETRY_INTERVAL)
                time.sleep(RETRY_INTERVAL)
                continue

            serial = device_info.get('serial_number') or FALLBACK_SERIAL
            if len(serial) < 4:
                serial = FALLBACK_SERIAL
            logger.info(
                "Found: {} (serial: {}, path: {})",
                device_info.get('product_string', ''),
                serial,
                device_info['path'],
            )

            key = generate_aes_key(serial, MODEL)
            cipher = AES.new(key.encode(), AES.MODE_ECB)

            # Open by path for a more specific match than VID/PID alone
            with hid.Device(path=device_info['path']) as dev:
                logger.info("Connected — streaming EEG")
                while not stop_event.is_set():
                    raw = dev.read(32, timeout=READ_TIMEOUT_MS)
                    if not raw:
                        continue
                    decrypted = cipher.decrypt(bytes(raw))
                    channels = [
                        int.from_bytes(decrypted[i:i + 2], 'big')
                        for i in range(0, 32, 2)
                    ]
                    loop.call_soon_threadsafe(data_queue.put_nowait, channels)

        except Exception as exc:
            logger.error("HID error: {} — retrying in {}s...", exc, RETRY_INTERVAL)
            time.sleep(RETRY_INTERVAL)


async def ws_handler(websocket) -> None:
    _clients.add(websocket)
    logger.info("Browser connected ({})", websocket.remote_address)
    try:
        await websocket.wait_closed()
    finally:
        _clients.discard(websocket)
        logger.info("Browser disconnected")


async def broadcast_loop(data_queue: asyncio.Queue) -> None:
    msg_template = {"names": CHANNEL_NAMES}
    while True:
        channels = await data_queue.get()
        if not _clients:
            continue
        msg = json.dumps({**msg_template, "channels": channels})
        dead = set()
        for ws in list(_clients):
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        _clients -= dead


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
