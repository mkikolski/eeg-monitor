"""
Extended decryption test + auth write attempt on char 81072f43.
Looking for a key variant that produces min/max spread < 1000 µV.
"""
import asyncio
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES

DEVICE_ADDRESS = "FB:38:12:E0:C3:38"
EEG_CHAR   = "81072f41-9f3d-11e3-a9dc-0002a5d5c51b"
AUTH_CHAR  = "81072f43-9f3d-11e3-a9dc-0002a5d5c51b"
SERIAL_STR = "EX0000B2C001205E"
# Raw serial bytes read from GATT 0x2a25
SERIAL_RAW = bytes([0xe5, 0x02, 0x10, 0x0c, 0x2b])
# MAC address bytes
MAC_BYTES  = bytes([0xFB, 0x38, 0x12, 0xE0, 0xC3, 0x38])

def to_uv(hi, lo):
    return ((hi * 0.128205128205129) + 4201.02564096001) + ((lo - 128) * 32.82051289)

def extract_channels(dec):
    vals = [to_uv(dec[i], dec[i+1]) for i in range(2, 16, 2)]
    vals += [to_uv(dec[i], dec[i+1]) for i in range(18, 32, 2)]
    return vals

def spread(vals):
    return max(vals) - min(vals)

def try_key(raw64, label, key, xor_byte=None):
    for offset, half in [(0, "A"), (32, "B")]:
        chunk = bytes(raw64[offset:offset+32])
        if xor_byte is not None:
            chunk = bytes(b ^ xor_byte for b in chunk)
        try:
            dec = AES.new(key, AES.MODE_ECB).decrypt(chunk)
            ch = extract_channels(dec)
            s = spread(ch)
            flag = " *** TIGHT ***" if s < 800 else ""
            print(f"  {label} half-{half}: spread={s:.0f}  ({min(ch):.0f}–{max(ch):.0f}){flag}")
        except Exception as e:
            print(f"  {label} half-{half}: ERROR {e}")

# ---- key definitions -------------------------------------------------------

def pad16(b):
    """Pad/truncate bytes to 16."""
    return (b + b'\x00' * 16)[:16]

KEYS = {
    # current scrambled pattern
    "scrambled": (lambda s: (lambda b: bytes([b[-1],b[-2],b[-4],b[-4],b[-2],b[-1],b[-2],b[-4],b[-1],b[-4],b[-3],b[-2],b[-1],b[-2],b[-2],b[-3]]))(s.encode()))(SERIAL_STR),
    # full serial as literal key bytes
    "full-serial-literal": SERIAL_STR.encode()[:16],
    # ABCDEFGHIJKL suffix
    "serial4+ABCDEFGHIJKL": SERIAL_STR.encode()[-4:] + b"ABCDEFGHIJKL",
    # raw GATT serial padded
    "gatt-serial-padded": pad16(SERIAL_RAW),
    # MAC padded
    "mac-padded": pad16(MAC_BYTES),
    # MAC repeated
    "mac-x3": (MAC_BYTES * 3)[:16],
    # all zeros
    "null-key": b'\x00' * 16,
    # all 0x55
    "0x55-key": b'\x55' * 16,
}

# ---- capture ---------------------------------------------------------------

captured_before = []
captured_after  = []

def make_cb(buf):
    def cb(_, data):
        if len(buf) < 3:
            buf.append(bytes(data))
    return cb

async def main():
    dev = await BleakScanner.find_device_by_address(DEVICE_ADDRESS, timeout=15)
    print(f"Found: {dev.name}\nConnecting ...")

    async with BleakClient(dev) as client:
        # Capture baseline packets
        client.services  # ensure services discovered
        await client.start_notify(EEG_CHAR, make_cb(captured_before))
        print("Capturing 3 baseline packets ...")
        while len(captured_before) < 3:
            await asyncio.sleep(0.05)
        await client.stop_notify(EEG_CHAR)

        # Try writing serial to auth char
        print(f"\nWriting serial bytes to {AUTH_CHAR} ...")
        for payload in [
            SERIAL_STR.encode(),
            SERIAL_RAW,
            bytes([0x01]),
            bytes([0x00]),
        ]:
            try:
                await client.write_gatt_char(AUTH_CHAR, payload, response=True)
                print(f"  wrote {payload.hex()} → ok")
            except Exception as e:
                try:
                    await client.write_gatt_char(AUTH_CHAR, payload, response=False)
                    print(f"  wrote {payload.hex()} (no-rsp) → ok")
                except Exception as e2:
                    print(f"  wrote {payload.hex()} → {e2}")

        # Capture after write
        await client.start_notify(EEG_CHAR, make_cb(captured_after))
        print("Capturing 3 post-write packets ...")
        while len(captured_after) < 3:
            await asyncio.sleep(0.05)
        await client.stop_notify(EEG_CHAR)

    print("\n===== BASELINE PACKET (key search) =====")
    pkt = captured_before[0]
    for name, key in KEYS.items():
        try_key(pkt, name, key, xor_byte=None)
        try_key(pkt, name+"[xor55]", key, xor_byte=0x55)

    print("\n===== POST-WRITE PACKET =====")
    if captured_after:
        pkt2 = captured_after[0]
        print(f"Before: {captured_before[0][:16].hex()}")
        print(f"After:  {pkt2[:16].hex()}")
        print("(same structure = write had no effect; different/tighter = progress)")
        for name, key in KEYS.items():
            try_key(pkt2, name, key, xor_byte=None)

asyncio.run(main())
