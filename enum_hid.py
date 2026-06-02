import os
from pathlib import Path

if hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(str(Path(__file__).resolve().parent))

import hid

print(f"{'VID':>6}  {'PID':>6}  {'Usage page':>10}  {'Usage':>6}  Product / Manufacturer / Serial")
print("-" * 90)
for d in sorted(hid.enumerate(), key=lambda x: (x['vendor_id'], x['product_id'])):
    vid = d['vendor_id']
    pid = d['product_id']
    print(
        f"0x{vid:04x}  0x{pid:04x}  "
        f"0x{d.get('usage_page', 0):08x}  "
        f"0x{d.get('usage', 0):04x}  "
        f"{d.get('manufacturer_string','')!r} / {d.get('product_string','')!r} / {d.get('serial_number','')!r}"
    )
