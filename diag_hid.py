import os, time
from pathlib import Path

if hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(str(Path(__file__).resolve().parent))

import hid

VENDOR_ID = 0x1234
PRODUCT_ID = 0xed02

def try_read(dev, label, count=10, size=32, timeout=300):
    got = 0
    for _ in range(count):
        raw = dev.read(size, timeout=timeout)
        if raw:
            got += 1
            if got == 1:
                print(f"  ✓ [{label}] first packet ({len(raw)}B): {bytes(raw).hex()}")
    if not got:
        print(f"  ✗ [{label}] no data")
    return got > 0

print(f"Opening 0x{VENDOR_ID:04x}/0x{PRODUCT_ID:04x} ...")
dev = hid.Device(VENDOR_ID, PRODUCT_ID)
print(f"  serial: {dev.serial}")

print("\n--- baseline read (no init) ---")
try_read(dev, "baseline", count=5)

# Known Emotiv EPOC wake sequences found in open-source reverse engineering
wake_sequences = [
    ("set mode 0x01",       [0x00, 0x01]),
    ("set mode 0x00",       [0x00, 0x00]),
    ("enable stream",       [0x00, 0x04]),
    ("enable stream alt",   [0x00, 0x02]),
    ("EPOC+ start",         [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ("feature report 0",    None),   # use get_feature_report instead
]

for label, payload in wake_sequences:
    if payload is None:
        try:
            data = dev.get_feature_report(0, 33)
            print(f"\n--- feature report 0: {bytes(data).hex()} ---")
        except Exception as e:
            print(f"\n--- feature report 0: {e} ---")
        continue

    print(f"\n--- write: {label} ---")
    try:
        dev.write(bytes(payload))
        print(f"  write ok")
    except Exception as e:
        print(f"  write failed: {e}")

    if try_read(dev, label, count=10, size=32):
        print("  ^ DATA IS FLOWING after this command!")
        break
    if try_read(dev, label, count=5, size=64):
        print("  ^ DATA IS FLOWING (64B) after this command!")
        break

dev.close()
print("\nDone.")
