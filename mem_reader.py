import asyncio
import ctypes
import ctypes.wintypes
import struct
import pymem
import pymem.process

PROCESS   = "EmotivPRO.exe"
SAMPLE_HZ = 128
N_CH      = 14

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1',
    'O2',  'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4',
]

# ---------------------------------------------------------------------------
# Pointer chain (try first — fast, but breaks on every EmotivPRO restart)
# ---------------------------------------------------------------------------
MODULE      = "EmotivPRO.exe"
BASE_OFF    = 0x02AB4268
CHAIN       = [0xFC0, 0x70, 0x70, 0x380]   # CE sqlite: offset1→offset4, base→target order
DIRECT_ADDR = 0x187AA63E0A0   # last known runtime address — not stable

# 14 consecutive float64s, 8 bytes apart — confirmed by find_and_map_live_channels()
CHANNEL_OFFSETS = [
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28,
    0x30, 0x38, 0x40, 0x48, 0x50, 0x58,
    0x60, 0x68,
]

# CE-found offsets (diagnostic helpers only)
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
    """Scan every 8-byte aligned offset in [0, size) for raw EEG values (3000-7000 uV)."""
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


def live_offset_map(base: int = 0, size: int = 0x1200, wait: float = 0.25) -> None:
    """Diff two snapshots {wait}s apart from a known buffer base.
    Shows every 8-byte offset whose double value actually changed — these are
    the truly live write slots. Run while headset is on and EmotivPRO is streaming.
    Pass base=0 to auto-scan for the live buffer first."""
    import time
    pm = pymem.Pymem(PROCESS)
    if base == 0:
        base = _scan_for_buffer(pm)
        if base is None:
            print("[live_offset_map] could not locate live buffer — wear headset")
            return
        print(f"[live_offset_map] auto-found live buffer @ 0x{base:X}")
    print(f"Snapshot 1 from 0x{base:X} (size=0x{size:X}) …")
    try:
        snap1 = pm.read_bytes(base, size)
    except Exception as e:
        print(f"[live_offset_map] read failed: {e}")
        return
    time.sleep(wait)
    snap2 = pm.read_bytes(base, size)

    changed, eeg_range = [], []
    for i in range(0, size - 8, 8):
        v1 = struct.unpack_from('<d', snap1, i)[0]
        v2 = struct.unpack_from('<d', snap2, i)[0]
        if v1 != v2:
            in_range = 3000.0 < v2 < 7000.0
            changed.append((i, v1, v2, in_range))
            if in_range:
                eeg_range.append(i)

    print(f"\n{len(changed)} offsets changed  ({len(eeg_range)} in EEG µV range):\n")
    for off, v1, v2, in_range in changed:
        tag = "  *** EEG" if in_range else ""
        print(f"  +0x{off:04X}  {v1:10.3f}  ->  {v2:10.3f}{tag}")

    if eeg_range:
        print(f"\nLive EEG offsets (copy into CHANNEL_OFFSETS):\n  {[hex(o) for o in eeg_range]}")


def find_and_map_live_channels() -> None:
    """Two-snapshot whole-process scan independent of CHANNEL_OFFSETS.
    Finds every double that changed AND is in EEG range, then clusters
    them to reveal the true buffer base and channel offsets.
    Run with headset on and EmotivPRO streaming."""
    import time
    pm = pymem.Pymem(PROCESS)
    handle = pm.process_handle
    mbi = _MBI()
    addr = 0x10000
    regions: list[tuple[int, bytes]] = []
    total = 0

    print("Pass 1: reading writable regions…")
    while addr < (1 << 47):
        sz = _k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if sz == 0:
            addr += 0x1000
            continue
        next_addr = mbi.BaseAddress + mbi.RegionSize
        r_size = int(mbi.RegionSize)
        if (mbi.State == _MEM_COMMIT
                and (mbi.Protect & 0xFF) in _PAGE_RW
                and 8 <= r_size <= 8 * 1024 * 1024
                and total < 512 * 1024 * 1024):
            try:
                regions.append((int(mbi.BaseAddress), pm.read_bytes(int(mbi.BaseAddress), r_size)))
                total += r_size
            except Exception:
                pass
        addr = next_addr

    print(f"  {len(regions)} regions ({total // 1024 // 1024} MB total). Waiting 300 ms…")
    time.sleep(0.3)

    print("Pass 2: diffing…")
    live: list[tuple[int, float, float]] = []
    for base, s1 in regions:
        try:
            s2 = pm.read_bytes(base, len(s1))
        except Exception:
            continue
        if _HAS_NP:
            a1 = _np.frombuffer(s1, dtype='<f8')
            a2 = _np.frombuffer(s2, dtype='<f8')
            for idx in _np.nonzero((a1 != a2) & (a2 > 3000.0) & (a2 < 7000.0))[0]:
                live.append((base + int(idx) * 8, float(a1[idx]), float(a2[idx])))
        else:
            mv1, mv2 = memoryview(s1), memoryview(s2)
            for i in range(0, len(s1) - 8, 8):
                v1 = struct.unpack_from('<d', mv1, i)[0]
                v2 = struct.unpack_from('<d', mv2, i)[0]
                if v1 != v2 and 3000.0 < v2 < 7000.0:
                    live.append((base + i, v1, v2))
    del regions

    live.sort()
    print(f"\n{len(live)} live EEG-range doubles:\n")
    prev = None
    for abs_addr, v1, v2 in live:
        gap = f"  (+0x{abs_addr - prev:04X})" if prev is not None else ""
        print(f"  0x{abs_addr:016X}  {v1:10.3f} -> {v2:10.3f}{gap}")
        prev = abs_addr

    if len(live) >= 14:
        addrs = [a for a, _, _ in live]
        best_i, best_span = 0, float('inf')
        for i in range(len(addrs) - 13):
            span = addrs[i + 13] - addrs[i]
            if span < best_span:
                best_span, best_i = span, i
        base14 = addrs[best_i]
        offsets = [hex(addrs[best_i + j] - base14) for j in range(14)]
        print(f"\nTightest 14-channel cluster:  base=0x{base14:X}  span=0x{best_span:X}")
        print(f"CHANNEL_OFFSETS = {offsets}")


# ---------------------------------------------------------------------------
# Heap scan — fallback when pointer chain fails after EmotivPRO restart
# ---------------------------------------------------------------------------

class _MBI(ctypes.Structure):
    # MEMORY_BASIC_INFORMATION on x64 Windows (48 bytes)
    _fields_ = [
        ('BaseAddress',       ctypes.c_ulonglong),
        ('AllocationBase',    ctypes.c_ulonglong),
        ('AllocationProtect', ctypes.c_ulong),
        ('_pad1',             ctypes.c_ulong),   # covers PartitionId (WORD) + padding
        ('RegionSize',        ctypes.c_ulonglong),
        ('State',             ctypes.c_ulong),
        ('Protect',           ctypes.c_ulong),
        ('Type',              ctypes.c_ulong),
        ('_pad2',             ctypes.c_ulong),
    ]


_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.VirtualQueryEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_ulonglong,
                                  ctypes.POINTER(_MBI), ctypes.c_size_t]
_k32.VirtualQueryEx.restype  = ctypes.c_size_t

_MEM_COMMIT  = 0x1000
_PAGE_RW     = {0x04, 0x08, 0x40, 0x80}   # PAGE_READWRITE / WRITECOPY variants
_LAST_CH_OFF = max(CHANNEL_OFFSETS)        # 0x0EE0 — minimum buffer span

try:
    import numpy as _np
    _HAS_NP = True
except ImportError:
    _HAS_NP = False


def _find_candidates_in_region(data: bytes, base: int) -> list[int]:
    """Return absolute addresses of ALL positions in this region passing the fingerprint."""
    hits = []
    if _HAS_NP:
        arr   = _np.frombuffer(data, dtype='<f8')
        cands = _np.nonzero((arr > 3000.0) & (arr < 7000.0))[0]
        for idx in cands:
            byte_off = int(idx) * 8
            if byte_off + _LAST_CH_OFF + 8 > len(data):
                continue
            try:
                if all(3000.0 < struct.unpack_from('<d', data, byte_off + ch_off)[0] < 7000.0
                       for ch_off in CHANNEL_OFFSETS):
                    hits.append(base + byte_off)
            except struct.error:
                pass
    else:
        mv = memoryview(data)
        for i in range(0, len(data) - _LAST_CH_OFF - 8, 8):
            if not (3000.0 < struct.unpack_from('<d', mv, i)[0] < 7000.0):
                continue
            try:
                if all(3000.0 < struct.unpack_from('<d', mv, i + ch_off)[0] < 7000.0
                       for ch_off in CHANNEL_OFFSETS):
                    hits.append(base + i)
            except struct.error:
                pass
    return hits


def _scan_for_buffer(pm: pymem.Pymem) -> int | None:
    """Two-pass scan: collect ALL candidates, then verify liveness.
    The live 128 Hz buffer MUST update within 150 ms; static snapshot copies won't."""
    import time

    handle     = pm.process_handle
    mbi        = _MBI()
    addr       = 0x10000
    max_region = 128 * 1024 * 1024
    candidates: list[int] = []

    mode = "numpy" if _HAS_NP else "pure-python"
    print(f"[mem_reader] scanning heap ({mode}) — headset must be on…")

    while addr < (1 << 47):
        sz = _k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if sz == 0:
            addr += 0x1000
            continue
        next_addr = mbi.BaseAddress + mbi.RegionSize
        if (mbi.State == _MEM_COMMIT
                and (mbi.Protect & 0xFF) in _PAGE_RW
                and _LAST_CH_OFF + 8 <= mbi.RegionSize <= max_region):
            try:
                data = pm.read_bytes(int(mbi.BaseAddress), int(mbi.RegionSize))
                candidates.extend(_find_candidates_in_region(data, int(mbi.BaseAddress)))
            except Exception:
                pass
        addr = next_addr

    if not candidates:
        print("[mem_reader] scan complete — no candidates found (wear headset)")
        return None

    print(f"[mem_reader] {len(candidates)} candidate(s) — checking liveness…")

    snap1: dict[int, list[float]] = {}
    for cand in candidates:
        try:
            snap1[cand] = [struct.unpack('<d', pm.read_bytes(cand + off, 8))[0]
                           for off in CHANNEL_OFFSETS]
        except Exception:
            pass

    time.sleep(0.15)   # 150 ms → live 128 Hz buffer writes ~19 new samples

    for cand in candidates:
        if cand not in snap1:
            continue
        try:
            snap2 = [struct.unpack('<d', pm.read_bytes(cand + off, 8))[0]
                     for off in CHANNEL_OFFSETS]
            if snap2 != snap1[cand]:
                print(f"[mem_reader] live EEG buffer @ 0x{cand:X}")
                return cand
        except Exception:
            pass

    print(f"[mem_reader] none of {len(candidates)} candidate(s) is live — is EmotivPRO streaming?")
    return None


# ---------------------------------------------------------------------------
# Baseline correction
# ---------------------------------------------------------------------------

_EMA_ALPHA = 0.005
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
# Pointer chain resolution (fast path — works only when chain is still valid)
# ---------------------------------------------------------------------------

def _resolve_chain(pm: pymem.Pymem) -> int:
    if not CHAIN:
        return DIRECT_ADDR
    mod  = pymem.process.module_from_name(pm.process_handle, MODULE)
    addr = pm.read_ulonglong(mod.lpBaseOfDll + BASE_OFF)
    for off in CHAIN[:-1]:
        addr = pm.read_ulonglong(addr + off)
    return addr + CHAIN[-1]


# ---------------------------------------------------------------------------
# Main reader coroutine
# ---------------------------------------------------------------------------

async def mem_reader(queue: asyncio.Queue) -> None:
    interval      = 1.0 / SAMPLE_HZ
    pm            = None
    buf_addr      = None
    last          = None
    bad_streak    = 0
    stale_streak  = 0
    _frame_count  = 0

    while True:
        try:
            if pm is None:
                pm = pymem.Pymem(PROCESS)
                buf_addr = None
                last     = None
                bad_streak = 0
                print(f"[mem_reader] attached to {PROCESS}")
                queue.put_nowait({"event": "device_connected"})

            if buf_addr is None:
                # Fast path: try the static pointer chain first
                try:
                    candidate = _resolve_chain(pm)
                    v0 = struct.unpack('<d', pm.read_bytes(candidate, 8))[0]
                    if 3000.0 < v0 < 7000.0:
                        buf_addr = candidate
                        print(f"[mem_reader] buffer @ 0x{buf_addr:X} (pointer chain)")
                    else:
                        raise ValueError(f"ch0={v0:.1f} outside EEG range")
                except Exception as chain_err:
                    print(f"[mem_reader] chain failed ({chain_err}) — falling back to heap scan")
                    loop = asyncio.get_running_loop()
                    buf_addr = await loop.run_in_executor(None, _scan_for_buffer, pm)
                    if buf_addr is None:
                        print("[mem_reader] heap scan found nothing — retrying in 5s (wear headset)")
                        pm = None
                        await asyncio.sleep(5.0)
                        continue
                stale_streak = 0
                _frame_count = 0
                # Print initial raw values to confirm correct buffer
                init = [struct.unpack("<d", pm.read_bytes(buf_addr + off, 8))[0]
                        for off in CHANNEL_OFFSETS]
                print(f"[mem_reader] raw µV: ch0={init[0]:.1f} ch6={init[6]:.1f} ch13={init[13]:.1f}")

            samples = [
                struct.unpack("<d", pm.read_bytes(buf_addr + off, 8))[0]
                for off in CHANNEL_OFFSETS
            ]

            if not all(3000.0 < v < 7000.0 for v in samples):
                bad_streak += 1
                if bad_streak >= 20:
                    print(f"[mem_reader] {bad_streak} consecutive out-of-range frames — re-resolving")
                    buf_addr   = None
                    bad_streak = 0
                await asyncio.sleep(interval)
                continue
            bad_streak = 0

            if samples == last:
                stale_streak += 1
                if stale_streak >= 640:   # ~5 s of frozen values → wrong buffer
                    print(f"[mem_reader] buffer frozen {stale_streak} frames — re-scanning")
                    buf_addr     = None
                    stale_streak = 0
                await asyncio.sleep(interval)
                continue
            stale_streak = 0

            last = samples
            _frame_count += 1
            corrected = _apply_baseline(samples)
            if _frame_count % 32 == 0:
                print(f"[mem_reader] {_frame_count} frames pushed  raw={samples[0]:.1f}  corrected={corrected[0]:.3f}")
            queue.put_nowait(corrected)

        except pymem.exception.ProcessNotFound:
            if pm is not None:
                print("[mem_reader] EmotivPRO closed — waiting for restart…")
                queue.put_nowait({"event": "device_disconnected"})
            pm           = None
            buf_addr     = None
            last         = None
            bad_streak   = 0
            stale_streak = 0
            _frame_count = 0
            await asyncio.sleep(3.0)
            continue

        except Exception as exc:
            print(f"[mem_reader] error: {exc}")
            buf_addr = None

        await asyncio.sleep(interval)
