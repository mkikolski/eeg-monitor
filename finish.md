# EEG Monitor — Session Findings & Remaining Steps

## What Works Right Now

`python visualizer.py` with EmotivPRO running streams live 14-channel EEG to the browser dashboard at http://localhost:2139. Recording to CSV works via the REC button.

---

## Key Findings

### Data format
- Values stored as **float64 (double)**, NOT float32
- Raw values are **~4000–5000 µV** (absolute, not baseline-corrected)
- EMA baseline correction (alpha=0.005) is applied in mem_reader.py to zero-centre the signal
- EmotivPRO also stores baseline-corrected versions of the same channels nearby in memory (±50 µV range) — ignore those

### Buffer layout
- Buffer base (runtime, changes every restart): `0x1F9575C6E00` (last confirmed session)
- 14 channels are **packed as consecutive float64s**, 8 bytes apart, spanning only 0x68 (104) bytes
- Confirmed by `find_and_map_live_channels()` two-snapshot whole-process heap scan:

```
CHANNEL_OFFSETS = [
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28,
    0x30, 0x38, 0x40, 0x48, 0x50, 0x58,
    0x60, 0x68,
]
```

- The old offsets (spanning 0x0EE0 = 3808 bytes) were wrong — they came from `brute_scan()` which found unrelated EEG-range values across a large struct, not a real 14-channel array
- The heap scan found 4638 EEG-range doubles in the process (many ring-buffer / processing-queue copies); the tightest-14-cluster heuristic correctly selects the primary write buffer

### Pointer chain (static — survives process restart IF it works)
Found via Cheat Engine pointer scanner on address `0x187AA63E0A0`:

```
EmotivPRO.exe + 0x02AB4268  →  +0xFC0  →  +0x70  →  +0x70  →  +0x380
```

**NOTE:** CE pointer scanner sqlite export lists offsets in base→target order (offset1 is first
dereference, offset4 is the final add). CE's GUI displays them target→base (reversed), which
is what tripped us up in the first session — [0x380, 0x70, 0x70, 0xFC0] was the GUI order,
[0xFC0, 0x70, 0x70, 0x380] is the correct application order.

Resolution in Python (already in mem_reader.py):
```python
mod  = pymem.process.module_from_name(pm.process_handle, "EmotivPRO.exe")
addr = pm.read_ulonglong(mod.lpBaseOfDll + 0x02AB4268)
addr = pm.read_ulonglong(addr + 0xFC0)
addr = pm.read_ulonglong(addr + 0x70)
addr = pm.read_ulonglong(addr + 0x70)
buf_base = addr + 0x380   # runtime address, differs each session
```

Backup chain (also from sqlite row 26, same BASE_OFF):
```
EmotivPRO.exe + 0x02AB4268  →  +0xF60  →  +0x90  →  +0x70  →  +0x380
```

---

## Remaining Steps

### 1. Verify pointer chain survives restart (CRITICAL)
After headset charges and EmotivPRO is opened fresh:

```powershell
.venv\Scripts\activate
python -c "
import pymem, pymem.process, struct
pm = pymem.Pymem('EmotivPRO.exe')
mod = pymem.process.module_from_name(pm.process_handle, 'EmotivPRO.exe')
addr = pm.read_ulonglong(mod.lpBaseOfDll + 0x02AB4268)
addr = pm.read_ulonglong(addr + 0xFC0)
addr = pm.read_ulonglong(addr + 0x70)
addr = pm.read_ulonglong(addr + 0x70)
addr = addr + 0x380
v = struct.unpack('<d', pm.read_bytes(addr, 8))[0]
print(f'buf_base=0x{addr:X}  ch0={v:.2f}')
"
```

- If `ch0` is in 3000–7000 range: chain is stable, done.
- If it crashes or gives garbage: the chain didn't survive. Re-run Cheat Engine pointer scanner (same steps as before) and update `BASE_OFF` and `CHAIN` in `mem_reader.py`.

### 2. Verify channel order (cosmetic but useful)
Channel labels in CHANNEL_NAMES are currently assigned arbitrarily to the 14 offsets. Do the visual cross-check:

1. `python visualizer.py` → open http://localhost:2139
2. **Blink hard** → two channels should spike simultaneously → those are **AF3** and **AF4** (first and last in the standard order)
3. **Clench jaw** → **T7** and **T8** should spike (temporal channels)
4. If the labels don't match the spikes, reorder `CHANNEL_NAMES` in `mem_reader.py` to match

### 3. (Optional) If pointer chain fails permanently
Fall back to a session-start scan. At EmotivPRO startup, run `brute_scan()` to re-discover the buffer base, then hard-code `DIRECT_ADDR` for that session. The 14 `CHANNEL_OFFSETS` are stable and do NOT need re-scanning (they're relative to the buffer base, which moves, but the offsets within it stay fixed).

---

## Files

| File | Purpose |
|---|---|
| `visualizer.py` | asyncio server — serves dashboard, WebSocket, calls mem_reader |
| `mem_reader.py` | pymem reader — pointer chain, channel offsets, EMA baseline, queue feeder |
| `dashboard.html` | browser UI — 14-channel scrolling EEG + REC button → CSV download |
| `continue.md` | original Windows handoff plan (background, now superseded by this file) |

## How to run
```powershell
.venv\Scripts\activate
python visualizer.py
# open http://localhost:2139
```

EmotivPRO must be open and streaming before or after starting visualizer.py (mem_reader retries every 3s).
