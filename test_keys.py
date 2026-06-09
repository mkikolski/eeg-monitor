"""
Offline key detection tool.

Usage:
  python test_keys.py <serial_hex> <btsnoop.cfa> [--xor]
  python test_keys.py E502100C capture.cfa

Reads EEG notifications from a btsnoop capture and scores all key candidates.
Prints every candidate with score >5% so you can narrow down the correct key.
"""
import hashlib
import struct
import sys
from Crypto.Cipher import AES


BTSNOOP_MAGIC = b'btsnoop\x00'
ATT_NOTIFICATION = 0x1b
EEG_HANDLE = None  # auto-detect from most-used notify handle


# ---------------------------------------------------------------------------
# Btsnoop parser (same logic as parse_ble.py)
# ---------------------------------------------------------------------------

def parse_btsnoop(path):
    records = []
    with open(path, 'rb') as f:
        magic = f.read(8)
        assert magic == BTSNOOP_MAGIC, f"Not a btsnoop file: {magic!r}"
        _version, _datalink = struct.unpack('>II', f.read(8))
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                break
            orig_len, inc_len, flags, drops = struct.unpack('>IIII', hdr[:16])
            data = f.read(inc_len)
            if len(data) < inc_len:
                break
            from_remote = bool(flags & 1)
            records.append((from_remote, data))
    return records


def extract_eeg_payloads(records):
    """Return list of raw notification payloads from the most-active handle."""
    from collections import defaultdict
    handle_payloads = defaultdict(list)

    for from_remote, data in records:
        if not data or data[0] != 0x02:  # ACL only
            continue
        if len(data) < 9:
            continue
        l2cap = data[5:]
        if len(l2cap) < 5:
            continue
        cid = struct.unpack('<H', l2cap[2:4])[0]
        if cid != 0x0004:
            continue
        att = l2cap[4:]
        if not att or att[0] != ATT_NOTIFICATION:
            continue
        if not from_remote or len(att) < 3:
            continue
        handle = struct.unpack('<H', att[1:3])[0]
        payload = att[3:]
        handle_payloads[handle].append(bytes(payload))

    if not handle_payloads:
        return []

    # Pick the handle with the most packets (that's the EEG stream)
    best_handle = max(handle_payloads, key=lambda h: len(handle_payloads[h]))
    payloads = handle_payloads[best_handle]
    print(f"EEG handle 0x{best_handle:04x}: {len(payloads)} packets, "
          f"payload size={len(payloads[0])}B")
    return payloads


# ---------------------------------------------------------------------------
# Key candidates
# ---------------------------------------------------------------------------

def key_candidates(serial_hex: str) -> list[tuple[str, bytes]]:
    out = []
    s = serial_hex.encode()
    su = serial_hex.upper().encode()

    if len(s) >= 4:
        out.append(("model6",      bytes([s[-1], s[-2], s[-3], s[-4]]) + b'ABCDEFGHIJKL'))
        out.append(("model6-up",   bytes([su[-1], su[-2], su[-3], su[-4]]) + b'ABCDEFGHIJKL'))
        out.append(("model2",      bytes([
            s[-1], 0x00, s[-2], ord('T'), s[-3], 0x10, s[-4], ord('B'),
            s[-1], 0x00, s[-2], ord('H'), s[-3], 0x00, s[-4], ord('P'),
        ])))
        out.append(("gen-v2",      bytes([
            s[-1], s[-2], s[-4], s[-4], s[-2], s[-1], s[-2], s[-4],
            s[-1], s[-4], s[-3], s[-2], s[-1], s[-2], s[-2], s[-3],
        ])))
        out.append(("hex-ascii",   (s * 2)[:16]))
        out.append(("md5-hex",     hashlib.md5(s).digest()))
        out.append(("md5-hex-up",  hashlib.md5(su).digest()))
        out.append(("sha1-hex",    hashlib.sha1(s).digest()[:16]))
        out.append(("sha1-hex-up", hashlib.sha1(su).digest()[:16]))
        out.append(("sha256-hex",  hashlib.sha256(s).digest()[:16]))

    # Try interpreting the hex string as raw bytes
    try:
        raw = bytes.fromhex(serial_hex)
        if len(raw) >= 4:
            out.append(("raw4-zero",    (raw[:4] + bytes(16))[:16]))
            out.append(("raw4-repeat",  (raw[:4] * 4)[:16]))
            out.append(("raw-repeat",   (raw * 4)[:16]))
            out.append(("raw-zero",     (raw + bytes(16))[:16]))
            out.append(("md5-raw",      hashlib.md5(raw).digest()))
            out.append(("sha1-raw",     hashlib.sha1(raw).digest()[:16]))
            if len(raw) >= 16:
                out.append(("raw16",    raw[:16]))
                out.append(("raw16-rev", raw[:16][::-1]))
    except ValueError:
        pass

    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def counter_score(decrypted: list[bytes]) -> float:
    if len(decrypted) < 3:
        return 0.0
    hits = sum(
        (decrypted[i][0] - decrypted[i - 1][0]) % 128 == 1
        for i in range(1, len(decrypted))
    )
    return hits / (len(decrypted) - 1)


def score_key(key: bytes, payloads: list[bytes], use_xor: bool) -> float:
    dec = []
    for ct in payloads[:100]:
        raw = bytes(b ^ 0x55 for b in ct) if use_xor else ct
        chunk = raw[:32]
        if len(chunk) < 32:
            continue
        try:
            dec.append(AES.new(key, AES.MODE_ECB).decrypt(chunk))
        except Exception:
            return 0.0
    return counter_score(dec)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit("Usage: python test_keys.py <SERIAL_HEX> <btsnoop.cfa>")

    serial_hex = args[0]
    cfa_path   = args[1]

    print(f"Serial: {serial_hex}")
    print(f"File:   {cfa_path}\n")

    records = parse_btsnoop(cfa_path)
    print(f"Total btsnoop records: {len(records)}")
    payloads = extract_eeg_payloads(records)
    if not payloads:
        sys.exit("No EEG notifications found")
    print(f"Testing {len(payloads)} packets…\n")

    candidates = key_candidates(serial_hex)
    results = []
    for name, key in candidates:
        for use_xor in (False, True):
            score = score_key(key, payloads, use_xor)
            label = f"{name}{'|xor' if use_xor else ''}"
            results.append((score, label, key, use_xor))

    results.sort(reverse=True)
    print(f"{'Score':>6}  {'Candidate':<30}  Key (hex)")
    print("-" * 80)
    for score, label, key, use_xor in results:
        if score > 0.05:
            print(f"{score:6.1%}  {label:<30}  {key.hex()}")

    winner_score, winner_label, winner_key, winner_xor = results[0]
    print(f"\nBest: {winner_label}  score={winner_score:.1%}  key={winner_key.hex()}")
    if winner_score >= 0.6:
        print("✓ Key detected with confidence!")
    else:
        print("✗ No confident match — key may use a different derivation.")
        print("  Try running with --show-all to see all candidates.")


if __name__ == '__main__':
    main()
