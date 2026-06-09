# MockEEG — Windows Handoff (RPM/WPM Path)

You're picking this up on a **Windows 10** machine. The user previously tried two paths on Linux/Android and both stalled. See `handoff.md` for the full backstory; this file is the new plan.

## Goal

Stream real-time 14-channel EEG from an **Emotiv EPOC X** headset into the existing browser dashboard. The dashboard (`dashboard.html`) already works — it just needs a stream of decoded float samples over WebSocket on port `2140`.

```json
// Each frame the dashboard expects:
{"names": ["AF3","F7","F3","FC5","T7","P7","O1","O2","P8","T8","FC6","F4","F8","AF4"],
 "channels": [<14 floats, µV>]}
```

## Why we're doing it this way

| Path | Status |
|---|---|
| Linux BLE direct (bleak + AES decrypt) | **Blocked** — bluetoothd 5.84 crashes on every `start_notify`. AES key derivation also unknown. |
| Android APK Frida hook | **Blocked** — `AES_set_*` never fires; `AES_ecb_encrypt` in `libEmbeddedLibQt.so` only fires when actively streaming, which we couldn't sustain. App uses static-linked libcrypto so the symbol is internal. |
| Decrypt EmotivPro's local DB | **Dead end** — DB is SQLCipher+Parquet-AES-GCM wrapped by a DPAPI master key. Even decrypted it stores derived metrics, not raw EEG. |
| **Memory scraping on Windows (this plan)** | Untested but should be the fastest path. |

## The plan

The official **EmotivPRO** Windows app already decrypts the headset and renders live waveforms. The decoded floats are sitting in its process memory. We attach with `ReadProcessMemory` (via `pymem`) and copy them out. No crypto to solve — we let Emotiv's own app do all the BLE / AES work.

### Phase 1 — Find the buffer offset (Cheat Engine, one-time, ~15 min)

1. Install EmotivPRO on Windows. Pair the EPOC X (`EPOCX (E502100C)`). Confirm waveforms render in EmotivPRO's UI.
2. Install **Cheat Engine** (https://cheatengine.org) — yes it's the game-hacking tool. Same tech.
3. Launch Cheat Engine → File → Open Process → select `EmotivPRO.exe`.
4. Settings: **Value Type = Float**, **Scan Type = Unknown initial value**, leave region defaults.
5. Click **First Scan**. Will return millions of addresses.
6. Click **Next Scan** with **Scan Type = Changed value**. Repeat 5–10 times.
7. Address pool shrinks to dozens. Among them: the EEG ring buffer.
8. Add a few candidates to the bottom panel, click "Memory View" / right-click → "Browse this memory region". The EEG buffer looks like **14 floats in a sensible µV range** sitting contiguously. From `visualizer.py:160`, the µV calibration is:
   ```
   ((hi * 0.128205…) + 4201.025…) + ((lo - 128) * 32.820…)
   ```
   So expect baseline ~**4000–5000**, swinging maybe ±2000 with movement / blinks. If you see 14 contiguous floats all in that range fluctuating in sync with the EmotivPRO chart, you've found it.
9. Right-click the address → **Find out what writes to this address**. Let it sit a moment. The write instruction's source register holds the buffer's base pointer.
10. Backtrace that pointer through CE's "Pointer scanner" → save a **static pointer chain**:
    ```
    libEmotivPRO.dll + 0x00ABCDEF → +0x18 → +0x40 → buf
    ```
    (offsets will differ; that's an illustrative shape)
11. **Verify**: restart EmotivPRO, re-resolve the chain, confirm it lands on a buffer that still fluctuates in EEG range. The chain must survive a process restart — otherwise it's a heap address that won't be reliable.

Save the resolved chain into `continue.md` (this file) under "Resolved offsets" below.

### Phase 2 — Python reader

`mem_reader.py` (you will write this) replaces the `ble_reader` coroutine in `visualizer.py`. Skeleton:

```python
# mem_reader.py
import asyncio
import struct
import time
import pymem
import pymem.process

PROCESS  = "EmotivPRO.exe"
MODULE   = "libEmotivPRO.dll"             # confirm exact name in Phase 1
BASE_OFF = 0x00ABCDEF                     # ← fill in from CE
CHAIN    = [0x18, 0x40]                   # ← fill in from CE; last offset is added directly to the buffer base
SAMPLE_HZ = 128                           # EPOC X sample rate

CHANNEL_NAMES = [
    'AF3', 'F7', 'F3', 'FC5', 'T7', 'P7', 'O1',
    'O2',  'P8', 'T8', 'FC6', 'F4', 'F8', 'AF4',
]

def resolve_chain(pm: pymem.Pymem) -> int:
    mod = pymem.process.module_from_name(pm.process_handle, MODULE)
    addr = pm.read_ulonglong(mod.lpBaseOfDll + BASE_OFF)
    for off in CHAIN[:-1]:
        addr = pm.read_ulonglong(addr + off)
    return addr + CHAIN[-1]

async def mem_reader(queue: asyncio.Queue) -> None:
    pm = pymem.Pymem(PROCESS)
    buf_addr = resolve_chain(pm)
    last_frame = None
    interval = 1.0 / SAMPLE_HZ
    while True:
        try:
            raw = pm.read_bytes(buf_addr, 14 * 4)        # 14 × float32
            samples = list(struct.unpack("<14f", raw))
            # only push new frames (dedupe so we don't spam the same buffer)
            if samples != last_frame:
                queue.put_nowait(samples)
                last_frame = samples
        except Exception as exc:
            # process closed, buffer moved — re-resolve
            print(f"re-resolving chain after error: {exc}")
            await asyncio.sleep(0.5)
            try:
                buf_addr = resolve_chain(pm)
            except Exception:
                pm = pymem.Pymem(PROCESS)
                buf_addr = resolve_chain(pm)
        await asyncio.sleep(interval)
```

### Phase 3 — Wire into `visualizer.py`

In `visualizer.py:main()` replace:
```python
ble_reader(data_queue := asyncio.Queue()),
```
with:
```python
from mem_reader import mem_reader
mem_reader(data_queue := asyncio.Queue()),
```

The existing `broadcast_loop` and `ws_handler` already do the right thing — they just need 14-float lists pushed into the queue.

### Phase 4 — Validate

1. EmotivPRO running and showing live waveforms.
2. `python visualizer.py` — should print "Dashboard → http://localhost:2139".
3. Browser to http://localhost:2139 — waveforms should mirror what EmotivPRO shows. There may be a small offset (different ring positions) but they should track in real time.

## Dev environment

The project uses `uv`. To get a Windows venv:

```powershell
uv venv
.venv\Scripts\activate
uv add pymem psutil
uv sync
```

`pymem` requires admin or the same user account that launched `EmotivPRO.exe`. The visualizer must be run from the same user session.

## Channel order & calibration reference

EmotivPRO will give you values in µV already calibrated. Order in the in-memory buffer is **unknown** until you confirm by visual cross-check against EmotivPRO's UI:

1. Have user blink hard while watching the dashboard — the two big spikes should be **AF3** and **AF4** (frontal). Note their column indices.
2. Have user clench jaw — **T7, T8** should spike.
3. From those two tests you can fix the index ordering. If it doesn't match the order above, fix the mapping in `mem_reader.py` before pushing to the queue.

If EmotivPRO stores in their original raw HID-decode order (see `visualizer.py:166` for the swap pattern), use the same swaps.

## If Cheat Engine isn't an option / fallback

Pure-Python differential scan (slower, no GUI):

```python
# Sketch — scan all heap pages, keep addresses where 14 contiguous floats
# all stay in [3000, 6500] and all change between snapshots.
import pymem
pm = pymem.Pymem("EmotivPRO.exe")
# 1. enumerate readable regions via VirtualQueryEx
# 2. read each region into a bytes buffer
# 3. sliding 56-byte window: try struct.unpack("<14f", w); check range
# 4. snapshot twice, keep windows where ≥10 of the 14 floats differ
# 5. print survivors as (addr, sample1, sample2)
```

This will take minutes to scan the whole address space but works headlessly. CE does the same thing 1000× faster.

## Resolved offsets

Fill in once Phase 1 is complete:

```
EmotivPRO version : ____
Module name       : ____
Base offset       : 0x____
Pointer chain     : [0x__, 0x__, …]
Confirmed sample rate: ___ Hz
Confirmed dtype   : float32 / float64
Buffer layout     : single frame / ring of N frames
```

## Files in this repo

| File | What it does |
|---|---|
| `visualizer.py` | The asyncio server. Currently has Linux BLE reader — replace its reader coroutine. |
| `dashboard.html` | Browser dashboard. No changes needed. |
| `handoff.md` | Previous (Linux + Android) attempt notes. Background only. |
| `read_db.py` | Encrypted-parquet inspector. Not relevant to this path. |
| `mem_reader.py` | **You will create this.** |

## Out of scope

- Don't try to decrypt anything in `database/`. That's a dead end (see `handoff.md`).
- Don't touch the Linux BLE path.
- Don't reverse-engineer EmotivPRO's network calls — we only need its in-memory buffer.

## Done criteria

`python visualizer.py` on Windows with EmotivPRO running shows the same waveforms in the browser dashboard as in EmotivPRO's chart view, updated in real time, with correct channel labels.
