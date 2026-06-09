# MockEEG — Agent Handoff Document

## Goal
Real-time EEG visualisation from an Emotiv EPOC X headset on Linux.
The browser dashboard (`dashboard.html`) already exists and works — it just needs a stream of decoded channel packets over WebSocket on port 2140.

---

## Device Facts
| Property | Value |
|----------|-------|
| Device name | `EPOCX (E502100C)` |
| BLE MAC | `FB:38:12:E0:C3:38` (LE random) |
| Serial (GATT 0x2a25) | `e502100c2b` (5 bytes raw) |
| Serial (hex string) | `E502100C` |
| Config char (0x1d) | `0080000e800c` → 14 channels, 800c sampling |
| Encryption | AES-128-ECB, key derived from serial |
| Counter heuristic | decrypted byte[0] increments by 1 mod 128 |

### GATT layout (confirmed via bleak enumeration)
| UUID suffix | Handle | CCCD handle | Properties |
|-------------|--------|-------------|------------|
| 81072f41 | — | 0x0015 | notify |
| 81072f42 | — | 0x0018 | notify ← EEG stream |
| 81072f43 | — | 0x001b | write, notify |
| 81072f44 | 0x001d | — | read (config) |
| 0x2a25 | 0x0028 | — | read (serial) |
| 0x2a19 | 0x0020 | 0x0021 | read, notify (battery) |

---

## Linux BLE path — current status (BLOCKED)

`visualizer.py` successfully:
- Scans and finds the device
- Connects via BleakClient
- Reads serial, config, enumerates GATT

It FAILS at `start_notify()` because **bluetoothd 5.84 crashes** every connection.

### Root cause (confirmed via btmon)
1. Device sends `SMP: Security Request (Bonding, No MITM, SC)` ~7 ms after connection
2. BlueZ initiates LE Secure Connections re-pairing concurrently with GATT operations
3. bluetoothd logs `= Disconnected from D-Bus. Exiting.` 300 ms later — a clean exit, not a segfault
4. This repeats every connection cycle

### What was tried
- Added `await asyncio.sleep(3.0)` after connect — crash still occurs at `start_notify`
- `write_gatt_descriptor` for CCCD → `NotPermitted` (BlueZ 5.84 blocks direct CCCD writes; must use StartNotify)
- `client.pair()` → returns `None`, does nothing useful
- Removed and re-paired device via `bluetoothctl` → `AuthenticationFailed` (device had stale bond, needed pairing-mode power cycle)
- `JustWorksRepairing = never` in main.conf — not yet confirmed whether it prevents the crash

### Potential Linux fixes not yet tried
- Injecting into `Application.onCreate()` (earlier than Activity) — might prevent race
- Trying BlueZ 5.85+ if Fedora packages it
- Implementing a D-Bus PropertiesChanged signal listener as a replacement for start_notify (bypasses the crashing StartNotify/AcquireNotify codepath) — bleak's internal `_backend._bus` exposes the dbus-fast MessageBus

---

## Android APK path — current status (IN PROGRESS)

### What works
- APK was split: `base.apk` (Java) + `split_config.arm64_v8a.apk` (native libs)
- Rebuilt `base.apk` with zero modifications → **installs and runs correctly** → no signature check
- Frida gadget (`libfrida-gadget.so`, arm64) injected into `base.apk`'s `lib/arm64-v8a/` folder
- `System.loadLibrary("frida-gadget")` smali injection into `MyActivity.onCreate()` (`.locals 0` → `.locals 1`, two lines before `invoke-super`)
- App launches, freezes on splash, Frida attaches successfully

### Frida findings so far
- `AES_set_decrypt_key` and `AES_set_encrypt_key` in `libEmbeddedLibQt.so` are hooked but **never fire** even when the headset connects and streams
- `AES_ecb_encrypt` in `libEmbeddedLibQt.so` **did fire** (3 calls, `enc=0`) in one session but produced blank output due to a bug: `Array.from(ArrayBuffer)` is empty — must use `Array.from(new Uint8Array(...))`
- After fixing the hexStr bug, `AES_ecb_encrypt` stopped firing entirely in the next session — reason unclear (timing? different code path taken?)
- EVP hooks and `javax.crypto.Cipher` hook: no output

### Hypotheses for why AES_set_* doesn't fire
1. Key schedule is pre-computed from a cached serial at app startup (before headset connects) — but gadget loads before Qt, so this should still be caught
2. AES implementation is custom / AES-NI NEON instructions (no named key-setup call)
3. Key setup happens in `libEmotivPRO_arm64-v8a.so` (6.1 MB, the smaller lib) rather than `libEmbeddedLibQt.so` (84 MB)
4. Key schedule built by an unnamed internal function, not the exported OpenSSL symbols

### Next things to try (Frida)

**A. Hook `libEmotivPRO_arm64-v8a.so` instead**
```javascript
// AesCrypto::doCrypt signature (from jadx/nm):
// doCrypt(bool enc, const uchar* key, const uchar* iv, const uchar* in, int inLen, uchar* out, int& outLen)
// key = args[1], 16 bytes
var lib2 = Process.findModuleByName("libEmotivPRO_arm64-v8a.so");
if (lib2) {
    lib2.enumerateExports().forEach(function(e) {
        if (e.name.indexOf("doCrypt") !== -1 || e.name.indexOf("AesCrypto") !== -1) {
            console.log(e.name + " @ " + e.address);
            // hook e.address, read args[1] for key
        }
    });
}
```

**B. Scan ALL modules for AES_ecb_encrypt, not just libEmbeddedLibQt.so**
The function may be in a different `.so` that's loaded at runtime.
```javascript
Process.enumerateModules().forEach(function(mod) {
    mod.enumerateExports().forEach(function(e) {
        if (e.name === "AES_ecb_encrypt") {
            console.log("Found in: " + mod.name + " @ " + e.address);
        }
    });
});
```

**C. Capture decrypted plaintext from AES_ecb_encrypt onLeave**
When `AES_ecb_encrypt` fires with `enc=0`, `args[1]` (output buffer) contains the decrypted block.
Collecting 50+ consecutive outputs and checking if byte[0] increments mod 128 would confirm we have EEG data without needing the key.

**D. Hook BLE notification receipt in Java**
If the app receives raw BLE bytes in a Java callback before passing to native:
```javascript
Java.perform(function() {
    // Search for onCharacteristicChanged implementations
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            // look for BLE callback implementations
        },
        onComplete: function() {}
    });
});
```

**E. Smali modification (no Frida) — log EEG to file**
Alternative to Frida: use `apktool` to inject smali that writes raw BLE notification bytes to `/sdcard/eeg_dump.bin` via `FileOutputStream`. Pull with `adb pull`. Run `test_keys.py` against the dump.

### APK modification notes
- `apktool` + `uber-apk-signer` workflow confirmed working
- Must resign ALL splits with the same key before `adb install-multiple`
- Package name: find with `adb shell pm list packages | grep -i emotiv`
- Application class: `org.qtproject.qt.android.bindings.QtApplication`
- Main activity: `com.emotiv.emotivprov4.MyActivity`
- Injection currently in `MyActivity.onCreate()` — consider moving to `QtApplication.smali` for earlier load

---

## Files in /home/mkikolski/MockEEG

| File | Purpose |
|------|---------|
| `visualizer.py` | Main Linux BLE server (asyncio + WebSocket + HTTP) |
| `dashboard.html` | Browser EEG dashboard, 14 channels, Canvas waveforms |
| `parse_ble.py` | btsnoop .cfa parser — shows writes and notifications |
| `test_keys.py` | Offline AES key scorer against btsnoop captures |
| `hook_key.js` | Frida script (currently: AES_ecb_encrypt + AES_set_* hooks) |
| `pyproject.toml` | uv-managed deps: bleak, pycryptodome, websockets, loguru |

---

## Key derivation — what is known
From disassembly of `libEmbeddedLibQt.so`:
- `BTLEDeviceFactory::getDeviceKey(InputDeviceInformation const&)` at VA `0x26f6518` returns a `QByteArray` at offset `0x70` of the struct — the key is pre-computed and stored there
- `extractEmotivInfos()` at VA `0x273abec` reads GATT characteristics 0x2a24–0x2a28 to populate the struct
- `QCryptographicHash` is referenced in `libEmotivPRO_arm64-v8a.so` — some hash-based derivation

No key candidate in `test_keys.py` has scored ≥ 60% yet (all hash variants of serial tried). The key derivation likely incorporates model number (0x2a24), firmware (0x2a26), or hardware revision (0x2a27) in addition to the serial. **These GATT characteristics have not been read yet on the Linux side** — adding them to key candidates is low-hanging fruit.

## Decode packet logic (in visualizer.py)
```python
def decode_packet(data: bytes, key: bytes, use_xor: bool) -> list[float]:
    raw = bytes(b ^ 0x55 for b in data) if use_xor else data
    dec = AES.new(key, AES.MODE_ECB).decrypt(raw[:32])
    def to_uv(hi, lo):
        return ((hi * 0.128205128205129) + 4201.02564096001) + ((lo - 128) * 32.82051289)
    ch  = [to_uv(dec[i], dec[i+1]) for i in range(2,  16, 2)]
    ch += [to_uv(dec[i], dec[i+1]) for i in range(18, 32, 2)]
    ch[0],  ch[2]  = ch[2],  ch[0]
    ch[13], ch[11] = ch[11], ch[13]
    ch[1],  ch[3]  = ch[3],  ch[1]
    ch[10], ch[12] = ch[12], ch[10]
    return ch  # 14 floats, µV, order: AF3 F7 F3 FC5 T7 P7 O1 O2 P8 T8 FC6 F4 F8 AF4
```
