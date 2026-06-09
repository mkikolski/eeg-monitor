"""
Inspect db.parquet (EmotivPRO local DB) — handles Parquet Modular Encryption.

The file magic 'PARE' indicates encrypted footer. Without the master key we
can't decrypt the data, but we CAN inspect:
  - The encrypted-footer's key_metadata (KMS reference, plaintext column ID)
  - Any plaintext column names that leak from the schema
  - All printable strings (look for serial, key IDs, URIs)

Usage:
    python read_db.py              # db.parquet
    python read_db.py path.parquet [--key HEX]
"""
import re
import struct
import sys
from pathlib import Path


SERIAL = 'E502100C'


def banner(s: str) -> None:
    print('\n' + '=' * 78)
    print(s)
    print('=' * 78)


def find_printable_runs(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    out, run, start = [], bytearray(), 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not run:
                start = i
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append((start, run.decode('ascii', errors='replace')))
            run.clear()
    if len(run) >= min_len:
        out.append((start, run.decode('ascii', errors='replace')))
    return out


def find_utf16_runs(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    out, run, start = [], bytearray(), 0
    i = 0
    while i < len(data) - 1:
        b1, b2 = data[i], data[i + 1]
        if 32 <= b1 < 127 and b2 == 0:
            if not run:
                start = i
            run.append(b1)
            i += 2
            continue
        if len(run) >= min_len:
            out.append((start, run.decode('ascii', errors='replace')))
        run.clear()
        i += 1
    return out


def try_open_with_key(path: Path, key_hex: str) -> None:
    """Try to decrypt with a user-provided 16/24/32-byte AES key (hex)."""
    import pyarrow.parquet as pq
    key = bytes.fromhex(key_hex)
    print(f'Trying decryption with key={key_hex}  ({len(key)}B)')

    try:
        # PME supports a simple "envelope" decryption via a KMS callback.
        # The simplest path: pyarrow.parquet.encryption with a static KMS.
        from pyarrow.parquet.encryption import (
            CryptoFactory, KmsClient, EncryptionConfiguration, KmsConnectionConfig,
            DecryptionConfiguration,
        )

        class StaticKms(KmsClient):
            def __init__(self, k): super().__init__(); self._k = k
            def wrap_key(self, key_bytes, master_key_identifier):
                return key_bytes  # not used for decryption
            def unwrap_key(self, wrapped_key, master_key_identifier):
                print(f'   unwrap_key called for ID={master_key_identifier!r}')
                return self._k

        factory = CryptoFactory(lambda cfg: StaticKms(key))
        dec_cfg = DecryptionConfiguration(cache_lifetime_seconds=600)
        kms_cfg = KmsConnectionConfig()
        props = factory.file_decryption_properties(kms_cfg, dec_cfg)

        pf = pq.ParquetFile(path, decryption_properties=props)
        print('   ✓ schema decrypted OK')
        print(pf.schema_arrow)
        df = pf.read().to_pandas()
        print(f'   ✓ loaded {len(df)} rows')
        print(df.head(10))
    except Exception as exc:
        print(f'   ✗ failed: {type(exc).__name__}: {exc}')


def main() -> None:
    args = sys.argv[1:]
    key_hex = None
    if '--key' in args:
        i = args.index('--key')
        key_hex = args[i + 1]
        args = args[:i] + args[i + 2:]
    path = Path(args[0]) if args else Path('db.parquet')

    if not path.exists():
        sys.exit(f'No such file: {path}')

    data = path.read_bytes()
    banner(f'File: {path}  ({len(data):,} bytes)')

    head, tail = data[:4], data[-4:]
    print(f'Magic head: {head!r}    Magic tail: {tail!r}')
    if head == b'PARE' or tail == b'PARE':
        print('→ Parquet Modular Encryption (encrypted footer, AES-GCM-V1).')
    elif head == b'PAR1':
        print('→ Standard parquet (unencrypted).')
    else:
        print('→ Unknown magic — may not be parquet.')

    footer_len = struct.unpack('<I', data[-8:-4])[0]
    print(f'Footer length: {footer_len:,} B')
    footer = data[-(footer_len + 8):-8]
    print(f'Footer slice : [{len(data) - footer_len - 8}:{len(data) - 8}]')
    print(f'Footer first 64B: {footer[:64].hex()}')

    banner('Strings in footer (ASCII, ≥6 chars)')
    for off, s in find_printable_runs(footer):
        print(f'  +{off:6d}  {s}')

    banner('Strings in footer (UTF-16LE, ≥6 chars)')
    for off, s in find_utf16_runs(footer):
        print(f'  +{off:6d}  {s}')

    banner('Strings in WHOLE file (ASCII, ≥8 chars) — look for serial / key ID / URL')
    runs = find_printable_runs(data, min_len=8)
    keep = []
    for off, s in runs:
        sl = s.lower()
        if (SERIAL.lower() in sl or 'emotiv' in sl or 'http' in sl or
            'key' in sl or 'kms' in sl or 'uuid' in sl.replace('-', '') or
            len(s) >= 16):
            keep.append((off, s))
    for off, s in keep[:120]:
        print(f'  +{off:7d}  {s[:140]}')
    print(f'... total filtered: {len(keep)} (showing first 120)')

    # Look for any string matching a UUID pattern
    uuids = set()
    rx = re.compile(rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    for m in rx.finditer(data):
        uuids.add(m.group().decode())
    banner(f'UUIDs found: {len(uuids)}')
    for u in sorted(uuids):
        print(f'  {u}')

    if key_hex:
        banner(f'Attempting decryption with --key {key_hex}')
        try_open_with_key(path, key_hex)
    else:
        print('\n(Pass --key <hex> to attempt decryption with a candidate AES key.)')


if __name__ == '__main__':
    main()
