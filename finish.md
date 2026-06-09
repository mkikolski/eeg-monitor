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
- Buffer base (runtime, changes every restart): `0x187AA63E0A0`
- Each channel has a **ping-pong (2-slot) buffer** — two adjacent doubles, 8 bytes apart, alternating as write/read
- We read from the first slot of each pair (lower address)
- 14 channel offsets from buffer base (confirmed by brute_scan while headset worn):

```
CHANNEL_OFFSETS = [
    0x0000, 0x0240, 0x0260, 0x0500, 0x0600,
    0x07C0, 0x0900, 0x09C0, 0x09E0, 0x0A00,
    0x0AA0, 0x0CE0, 0x0D80, 0x0EE0,
]
```

### Pointer chain (static — survives process restart IF it works)
Found via Cheat Engine pointer scanner on address `0x187AA63E0A0`:

```
EmotivPRO.exe + 0x02AB4268  →  +0x380  →  +0x70  →  +0x70  →  +0xFC0
```

Resolution in Python (already in mem_reader.py):
```python
mod  = pymem.process.module_from_name(pm.process_handle, "EmotivPRO.exe")
addr = pm.read_ulonglong(mod.lpBaseOfDll + 0x02AB4268)
addr = pm.read_ulonglong(addr + 0x380)
addr = pm.read_ulonglong(addr + 0x70)
addr = pm.read_ulonglong(addr + 0x70)
buf_base = addr + 0xFC0   # should equal ~0x187AA63E0A0 (differs each session)
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
addr = pm.read_ulonglong(addr + 0x380)
addr = pm.read_ulonglong(addr + 0x70)
addr = pm.read_ulonglong(addr + 0x70)
addr = addr + 0xFC0
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
