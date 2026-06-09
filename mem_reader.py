import asyncio
import struct
import pymem
import pymem.process

PROCESS     = "EmotivPRO.exe"
SAMPLE_HZ   = 128
N_CH        = 14

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1',
    'O2',  'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4',
]

# ---------------------------------------------------------------------------
# Pointer chain — fill in after running CE pointer scanner on R8=0x187AA63E0A0
# ---------------------------------------------------------------------------
# Example shape once resolved:
#   MODULE   = "EmotivPRO.exe"
#   BASE_OFF = 0x01234567
#   CHAIN    = [0x18, 0x40]   # all but last are ptr dereferences; last is added directly
MODULE   = "EmotivPRO.exe"
BASE_OFF = 0x02AB4268
CHAIN    = [0x380, 0x70, 0x70, 0xFC0]

# Until the pointer chain is resolved, use the direct runtime address.
# THIS BREAKS ON EVERY EmotivPRO RESTART — replace with the chain above.
DIRECT_ADDR = 0x187AA63E0A0

# One offset per channel (first slot of each ping-pong pair), from brute_scan().
# ORDER IS TENTATIVE — verify channel mapping with blink/jaw test and fix CHANNEL_NAMES.
CHANNEL_OFFSETS = [
    0x0000, 0x0240, 0x0260, 0x0500, 0x0600,
    0x07C0, 0x0900, 0x09C0, 0x09E0, 0x0A00,
    0x0AA0, 0x0CE0, 0x0D80, 0x0EE0,
]

# Offsets from DIRECT_ADDR of all doubles CE found (CE_address - 4 - DIRECT_ADDR).
_CE_OFFSETS = [
    0x000, 0x008, 0x140, 0x148, 0x180, 0x188,
    0x248, 0x260, 0x2A0, 0x2A8, 0x508,
    0x5E0, 0x5E8, 0x620, 0x628, 0x640, 0x648,
    0x7C8, 0x800, 0x808, 0x840, 0x848,
    0x900, 0x920, 0x928, 0x9E8,
    0xC00, 0xC08, 0xC40, 0xC48, 0xD88,
    0xE00, 0xE08, 0xFC0, 0xFC8, 0xFE0, 0xFE8,
]

def scan_offsets() -> None:
    """Print current value at every CE-found offset. Run once while headset is on."""
    pm = pymem.Pymem(PROCESS)
    base = DIRECT_ADDR
    print(f"Scanning {len(_CE_OFFSETS)} offsets from 0x{base:X}:")
    for off in _CE_OFFSETS:
        raw = pm.read_bytes(base + off, 8)
        v = struct.unpack("<d", raw)[0]
        tag = "  <-- EEG?" if 3000.0 < v < 7000.0 else ""
        print(f"  +0x{off:04X}  {v:12.3f}{tag}")


def brute_scan(size: int = 0x1100) -> None:
    """Scan every 8-byte aligned offset in [0, size) for raw EEG values (3000-7000 uV).
    Run while headset is on and EmotivPRO is streaming. Should find all 14 channels."""
    pm = pymem.Pymem(PROCESS)
    base = DIRECT_ADDR
    hits = []
    for off in range(0, size, 8):
        try:
            v = struct.unpack("<d", pm.read_bytes(base + off, 8))[0]
            if 3000.0 < v < 7000.0:
                hits.append((off, v))
        except Exception:
            pass
    print(f"Found {len(hits)} raw EEG candidates (3000-7000 uV) in 0x{size:X} byte range:")
    for off, v in hits:
        print(f"  +0x{off:04X}  {v:.3f}")

# ---------------------------------------------------------------------------
# Baseline correction
# ---------------------------------------------------------------------------
# Raw values from the buffer are absolute µV (~4000–5000). Subtract a slow
# exponential moving average so the dashboard sees zero-centred signal.
_EMA_ALPHA = 0.005   # tau ≈ 200 samples (~1.5 s); slows drift removal
_baseline: list[float | None] = [None] * N_CH


def _apply_baseline(samples: list[float]) -> list[float]:
    out = []
    for i, v in enumerate(samples):
        if _baseline[i] is None:
            _baseline[i] = v
        else:
            _baseline[i] += _EMA_ALPHA * (v - _baseline[i])
        out.append(v - _baseline[i])
    return out


# ---------------------------------------------------------------------------
# Pointer resolution
# ---------------------------------------------------------------------------

def _resolve(pm: pymem.Pymem) -> int:
    if not CHAIN:
        return DIRECT_ADDR
    mod = pymem.process.module_from_name(pm.process_handle, MODULE)
    addr = pm.read_ulonglong(mod.lpBaseOfDll + BASE_OFF)
    for off in CHAIN[:-1]:
        addr = pm.read_ulonglong(addr + off)
    return addr + CHAIN[-1]


# ---------------------------------------------------------------------------
# Main reader coroutine — drop-in replacement for ble_reader
# ---------------------------------------------------------------------------

async def mem_reader(queue: asyncio.Queue) -> None:
    interval = 1.0 / SAMPLE_HZ
    pm       = None
    buf_addr = None
    last     = None

    while True:
        try:
            if pm is None:
                pm = pymem.Pymem(PROCESS)
                buf_addr = _resolve(pm)
                print(f"[mem_reader] attached to {PROCESS} — buffer @ 0x{buf_addr:X}")
                queue.put_nowait({"event": "device_connected"})

            samples = [
                struct.unpack("<d", pm.read_bytes(buf_addr + off, 8))[0]
                for off in CHANNEL_OFFSETS
            ]

            # Skip duplicate frames (buffer hasn't advanced yet)
            if samples == last:
                await asyncio.sleep(interval)
                continue
            last = samples

            queue.put_nowait(_apply_baseline(samples))

        except pymem.exception.ProcessNotFound:
            if pm is not None:
                print("[mem_reader] EmotivPRO closed — waiting for restart...")
                queue.put_nowait({"event": "device_disconnected"})
            pm = None
            buf_addr = None
            last = None
            await asyncio.sleep(3.0)
            continue

        except Exception as exc:
            print(f"[mem_reader] read error: {exc} — re-resolving chain")
            await asyncio.sleep(0.5)
            try:
                buf_addr = _resolve(pm)
            except Exception:
                pm = None

        await asyncio.sleep(interval)
