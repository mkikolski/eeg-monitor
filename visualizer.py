import asyncio
import hashlib
import json
import http.server
import subprocess
import threading
from pathlib import Path

from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from loguru import logger
import websockets

HTTP_PORT = 2139
WS_PORT   = 2140

EPOC_NAME        = "EPOCX"
EEG_NOTIFY_UUID  = "81072f42-9f3d-11e3-a9dc-0002a5d5c51b"
AUX_NOTIFY_UUID  = "81072f41-9f3d-11e3-a9dc-0002a5d5c51b"  # btsnoop: subscribed first (CCCD 0x0015)
CMD_NOTIFY_UUID  = "81072f43-9f3d-11e3-a9dc-0002a5d5c51b"
SERIAL_CHAR_UUID = "00002a25-0000-1000-8000-00805f9b34fb"

SCAN_TIMEOUT   = 15.0
RETRY_INTERVAL = 3

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1',
    'O2',  'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4',
]

_clients: set          = set()
_device_connected: bool = False


# ---------------------------------------------------------------------------
# Key candidates
# ---------------------------------------------------------------------------

def _key_candidates(serial_hex: str, serial_raw: bytes, mac: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    s = serial_hex.encode()         # e.g. b'E502100C'

    if len(s) >= 4:
        # emotiv_server.py model 6 (EPOC+)
        out.append(("model6",
            bytes([s[-1], s[-2], s[-3], s[-4]]) + b'ABCDEFGHIJKL'))
        # emotiv_server.py model 2 (EPOC standard)
        out.append(("model2", bytes([
            s[-1], 0x00, s[-2], ord('T'), s[-3], 0x10, s[-4], ord('B'),
            s[-1], 0x00, s[-2], ord('H'), s[-3], 0x00, s[-4], ord('P'),
        ])))
        # previous attempt in this repo
        out.append(("gen-v2", bytes([
            s[-1], s[-2], s[-4], s[-4], s[-2], s[-1], s[-2], s[-4],
            s[-1], s[-4], s[-3], s[-2], s[-1], s[-2], s[-2], s[-3],
        ])))
        # ASCII hex string repeated to 16 bytes
        out.append(("hex-ascii", (s * 2)[:16]))

        # Hash-based derivations (QCryptographicHash is used by the app)
        out.append(("md5-hex",    hashlib.md5(s).digest()))
        out.append(("sha1-hex",   hashlib.sha1(s).digest()[:16]))
        out.append(("sha256-hex", hashlib.sha256(s).digest()[:16]))
        # Uppercase serial
        out.append(("md5-hex-up",    hashlib.md5(s.upper()).digest()))
        out.append(("sha1-hex-up",   hashlib.sha1(s.upper()).digest()[:16]))

    # raw binary serial from 0x2a25 characteristic
    if len(serial_raw) >= 4:
        sb4 = serial_raw[:4]
        out.append(("raw4-zero",   (sb4   + bytes(16))[:16]))
        out.append(("raw4-repeat", (sb4   * 4        )[:16]))
        out.append(("raw5-zero",   (serial_raw[:5] + bytes(16))[:16]))
        # Hash of raw serial bytes
        out.append(("md5-raw",    hashlib.md5(serial_raw).digest()))
        out.append(("sha1-raw",   hashlib.sha1(serial_raw).digest()[:16]))
        # If serial is exactly 16 bytes, try it directly as the key
        if len(serial_raw) >= 16:
            out.append(("raw16",     serial_raw[:16]))
            out.append(("raw16-rev", serial_raw[:16][::-1]))
        # raw serial repeated / zero-padded to 16 bytes
        out.append(("raw-repeat", (serial_raw * 4)[:16]))
        out.append(("raw-zero",   (serial_raw   + bytes(16))[:16]))

    # BLE MAC address
    try:
        mb = bytes(int(x, 16) for x in mac.split(':'))
        out.append(("mac-repeat", (mb * 3)[:16]))
        out.append(("mac-zero",   (mb + bytes(16))[:16]))
        out.append(("md5-mac",    hashlib.md5(mb).digest()))
    except Exception:
        pass

    return out


# ---------------------------------------------------------------------------
# Key auto-detection via packet-counter heuristic
# ---------------------------------------------------------------------------

def _counter_score(decrypted: list[bytes]) -> float:
    """Fraction of consecutive packet pairs where byte[0] increments by 1 mod 128."""
    if len(decrypted) < 3:
        return 0.0
    hits = sum(
        (decrypted[i][0] - decrypted[i - 1][0]) % 128 == 1
        for i in range(1, len(decrypted))
    )
    return hits / (len(decrypted) - 1)


def detect_key(
    candidates: list[tuple[str, bytes]],
    ciphertexts: list[bytes],
) -> tuple[str, bytes, bool] | None:
    best_score = 0.0
    best_result = None
    n = min(40, len(ciphertexts))

    for name, key in candidates:
        for use_xor in (False, True):
            try:
                dec = []
                for ct in ciphertexts[:n]:
                    raw   = bytes(b ^ 0x55 for b in ct) if use_xor else ct
                    chunk = raw[:32]
                    if len(chunk) == 32:
                        dec.append(AES.new(key, AES.MODE_ECB).decrypt(chunk))
                score = _counter_score(dec)
                label = f"{name}{'|xor' if use_xor else ''}"
                if score > 0.1:
                    logger.debug("  {}: {:.0%}", label, score)
                if score > best_score:
                    best_score  = score
                    best_result = (label, key, use_xor)
            except Exception:
                continue

    if best_score >= 0.6 and best_result:
        label, key, use_xor = best_result
        logger.info("Key auto-detected: {} (counter score {:.0%})", label, best_score)
        return label, key, use_xor

    if best_score > 0:
        logger.warning(
            "Best key score {:.0%} — below 60%% threshold, collecting more packets...",
            best_score,
        )
    return None


# ---------------------------------------------------------------------------
# Packet decoding
# ---------------------------------------------------------------------------

def decode_packet(data: bytes, key: bytes, use_xor: bool) -> list[float]:
    raw = bytes(b ^ 0x55 for b in data) if use_xor else data
    dec = AES.new(key, AES.MODE_ECB).decrypt(raw[:32])

    def to_uv(hi: int, lo: int) -> float:
        return ((hi * 0.128205128205129) + 4201.02564096001) + ((lo - 128) * 32.82051289)

    ch  = [to_uv(dec[i], dec[i + 1]) for i in range(2,  16, 2)]   # bytes 2–15
    ch += [to_uv(dec[i], dec[i + 1]) for i in range(18, 32, 2)]   # bytes 18–31

    # reorder raw layout → AF3, F7, F3, FC5, T7, P7, O1, O2, P8, T8, FC6, F4, F8, AF4
    ch[0],  ch[2]  = ch[2],  ch[0]
    ch[13], ch[11] = ch[11], ch[13]
    ch[1],  ch[3]  = ch[3],  ch[1]
    ch[10], ch[12] = ch[12], ch[10]
    return ch


# ---------------------------------------------------------------------------
# BlueZ bond check
# ---------------------------------------------------------------------------

def _check_bonded(mac: str) -> bool:
    try:
        out = subprocess.run(
            ["bluetoothctl", "info", mac],
            capture_output=True, text=True, timeout=4
        ).stdout
        return "Paired: yes" in out
    except Exception:
        return False


# ---------------------------------------------------------------------------
# BLE reader (async, runs in the main event loop)
# ---------------------------------------------------------------------------

async def ble_reader(data_queue: asyncio.Queue) -> None:
    while True:
        try:
            logger.info("Scanning for {} (up to {}s)...", EPOC_NAME, SCAN_TIMEOUT)

            try:
                device = await BleakScanner.find_device_by_filter(
                    lambda d, _: bool(d.name and EPOC_NAME in d.name),
                    timeout=SCAN_TIMEOUT,
                )
            except AttributeError:
                # Older bleak: fall back to discover()
                found  = await BleakScanner.discover(timeout=SCAN_TIMEOUT)
                device = next((d for d in found if d.name and EPOC_NAME in d.name), None)

            if device is None:
                logger.warning("EPOC X not found — retrying in {}s", RETRY_INTERVAL)
                await asyncio.sleep(RETRY_INTERVAL)
                continue

            logger.info("Found: {} at {}", device.name, device.address)

            async with BleakClient(device, timeout=10.0) as client:
                # Device sends SMP Security Request right after encryption to re-bond
                # with LE Secure Connections. BlueZ crashes if GATT ops happen
                # concurrently with the SMP exchange — wait for it to finish.
                logger.debug("Waiting for SMP Security Request to settle...")
                await asyncio.sleep(3.0)
                if not client.is_connected:
                    logger.warning("Lost connection during SMP settle — retrying")
                    continue

                # read binary serial from device
                try:
                    serial_raw = bytes(await client.read_gatt_char(SERIAL_CHAR_UUID))
                except Exception:
                    serial_raw = bytes.fromhex("e502100c")

                # extract hex serial from device name "EPOCX (E502100C)"
                try:
                    serial_hex = device.name.split("(")[-1].rstrip(")")
                except Exception:
                    serial_hex = serial_raw[:4].hex().upper()

                logger.info("Serial hex={} raw={} ({}B)", serial_hex, serial_raw.hex(), len(serial_raw))

                # Enumerate GATT tree — confirms characteristic properties and handles
                for svc in client.services:
                    for ch in svc.characteristics:
                        descs = [f"0x{d.handle:04x}:{d.uuid[:8]}" for d in ch.descriptors]
                        logger.debug("  char {} props={} descs=[{}]",
                                     ch.uuid[:8], ch.properties, ", ".join(descs))

                # Read config char (81072f44) to trigger encryption before CCCD writes
                CONFIG_UUID = "81072f44-9f3d-11e3-a9dc-0002a5d5c51b"
                try:
                    cfg = bytes(await client.read_gatt_char(CONFIG_UUID))
                    logger.info("Config char: {}", cfg.hex())
                except Exception as e:
                    logger.debug("Config read skipped: {}", e)

                candidates = _key_candidates(serial_hex, serial_raw, device.address)
                logger.info("Trying {} key×xor combinations...", len(candidates) * 2)

                active: list = [None]       # [None | (label, key, use_xor)]
                buf:    list  = []          # raw encrypted packets

                def on_eeg(_handle, data: bytearray) -> None:
                    raw = bytes(data)

                    if active[0] is None:
                        buf.append(raw)
                        # attempt detection every 10 new packets
                        if len(buf) % 10 == 0:
                            result = detect_key(candidates, buf)
                            if result:
                                active[0] = result
                                logger.info("Streaming — key: {}", result[0])
                            elif len(buf) % 50 == 0:
                                logger.debug("Still searching — {} packets, best <60%", len(buf))
                        return

                    _, key, use_xor = active[0]
                    try:
                        data_queue.put_nowait(decode_packet(raw, key, use_xor))
                    except Exception as exc:
                        logger.debug("Decode error: {}", exc)

                logger.debug("bonded={} is_connected={}", _check_bonded(device.address), client.is_connected)

                # btsnoop showed Android app subscribing to 81072f41 (CCCD 0x0015) BEFORE
                # 81072f42 (CCCD 0x0018) — device requires this order.
                logger.debug("Subscribing to aux notify (81072f41, CCCD 0x0015)...")
                try:
                    await client.start_notify(AUX_NOTIFY_UUID, lambda *_: None)
                    logger.debug("Aux notify subscribed OK — is_connected={}", client.is_connected)
                except Exception as e:
                    logger.warning("Aux notify subscribe failed: {}", e)

                await asyncio.sleep(0.2)

                logger.debug("Subscribing to EEG notify (81072f42, CCCD 0x0018)...")
                await client.start_notify(EEG_NOTIFY_UUID, on_eeg)
                logger.debug("EEG notify subscribed OK — is_connected={}", client.is_connected)

                await asyncio.sleep(0.5)
                logger.debug("After settle — is_connected={}", client.is_connected)

                data_queue.put_nowait({"event": "device_connected"})
                logger.info("Subscribed — collecting packets for key detection...")

                while client.is_connected:
                    await asyncio.sleep(0.5)

        except Exception as exc:
            err = str(exc)
            # BlueZ races on cleanup when the device drops — not a real error
            if "UnknownObject" in err and "Disconnect" in err:
                logger.warning("Device dropped connection — retrying in {}s", RETRY_INTERVAL)
            else:
                logger.error("BLE error ({}): {} — retrying in {}s",
                             type(exc).__name__, exc, RETRY_INTERVAL)

        data_queue.put_nowait({"event": "device_disconnected"})
        await asyncio.sleep(RETRY_INTERVAL)


# ---------------------------------------------------------------------------
# WebSocket + broadcast
# ---------------------------------------------------------------------------

async def ws_handler(websocket) -> None:
    _clients.add(websocket)
    logger.info("Browser connected ({})", websocket.remote_address)
    try:
        await websocket.send(json.dumps({
            "event": "device_connected" if _device_connected else "device_disconnected"
        }))
        await websocket.wait_closed()
    finally:
        _clients.discard(websocket)
        logger.info("Browser disconnected")


async def broadcast_loop(data_queue: asyncio.Queue) -> None:
    global _device_connected
    while True:
        item = await data_queue.get()
        if isinstance(item, dict):
            _device_connected = item.get("event") == "device_connected"
        if not _clients:
            continue
        msg = json.dumps(item if isinstance(item, dict)
                         else {"names": CHANNEL_NAMES, "channels": item})
        dead = set()
        for ws in list(_clients):
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        _clients.difference_update(dead)


# ---------------------------------------------------------------------------
# HTTP server (serves dashboard.html)
# ---------------------------------------------------------------------------

def _start_http_server(port: int) -> None:
    dashboard = Path(__file__).parent / "dashboard.html"

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.rstrip("/") in ("", "/dashboard.html"):
                content = dashboard.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    http.server.HTTPServer(("0.0.0.0", port), _Handler).serve_forever()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    from loguru import logger as _log
    import sys
    _log.remove()
    _log.add(sys.stderr, level="DEBUG")

    threading.Thread(target=_start_http_server, args=(HTTP_PORT,), daemon=True).start()

    logger.info("Dashboard  →  http://localhost:{}", HTTP_PORT)
    logger.info("WebSocket  →  ws://localhost:{}", WS_PORT)

    async with websockets.serve(ws_handler, "0.0.0.0", WS_PORT):
        await asyncio.gather(
            ble_reader(data_queue := asyncio.Queue()),
            broadcast_loop(data_queue),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down.")
