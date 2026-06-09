"""
Parse btsnoop capture and extract Emotiv BLE writes and notifications.
Run with --debug to see raw packet breakdown when output is empty.
"""
import struct
import sys
from collections import defaultdict

BTSNOOP_MAGIC = b'btsnoop\x00'

ATT_READ_BY_TYPE_RSP = 0x09
ATT_WRITE_REQ        = 0x12
ATT_WRITE_CMD        = 0x52
ATT_NOTIFICATION     = 0x1b
ATT_INDICATION       = 0x1d

OPCODE_NAMES = {
    ATT_WRITE_REQ:  'WriteReq',
    ATT_WRITE_CMD:  'WriteCmd',
    ATT_NOTIFICATION: 'Notify',
    ATT_INDICATION:   'Indicate',
}

HCI_TYPES = {0x01: 'CMD', 0x02: 'ACL', 0x03: 'SCO', 0x04: 'EVT'}


def parse_btsnoop(path):
    with open(path, 'rb') as f:
        magic = f.read(8)
        if magic != BTSNOOP_MAGIC:
            sys.exit(f"Not a btsnoop file: {magic!r}")
        version, datalink = struct.unpack('>II', f.read(8))
        print(f"btsnoop version={version} datalink={datalink}")

        records = []
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                break
            orig_len, inc_len, flags, drops = struct.unpack('>IIII', hdr[:16])
            data = f.read(inc_len)
            if len(data) < inc_len:
                break
            # Android btsnoop: bit0=0 → host sent, bit0=1 → host received from controller/remote
            from_remote = bool(flags & 1)
            records.append((from_remote, data))
    return records


def iter_att(records, debug=False):
    hci_counts = defaultdict(int)
    cid_counts  = defaultdict(int)
    att_opcodes = defaultdict(int)

    for sent, data in records:
        if not data:
            continue

        hci_type = data[0]
        hci_counts[hci_type] += 1

        if hci_type != 0x02:   # only ACL
            continue
        if len(data) < 9:
            continue

        # ACL: bytes 1-2 handle/flags, 3-4 length, 5+ L2CAP
        l2cap = data[5:]
        if len(l2cap) < 5:
            continue

        cid = struct.unpack('<H', l2cap[2:4])[0]
        cid_counts[cid] += 1

        if cid != 0x0004:       # ATT channel
            continue

        att = l2cap[4:]
        if not att:
            continue

        opcode = att[0]
        att_opcodes[opcode] += 1
        yield sent, opcode, att[1:]

    if debug:
        print("\n--- DEBUG ---")
        print("HCI packet types found:")
        for k, v in sorted(hci_counts.items()):
            print(f"  0x{k:02x} ({HCI_TYPES.get(k, '?')}): {v}")
        print("L2CAP CIDs found (in ACL packets):")
        for k, v in sorted(cid_counts.items()):
            print(f"  0x{k:04x}: {v} packets")
        print("ATT opcodes found:")
        for k, v in sorted(att_opcodes.items()):
            print(f"  0x{k:02x}: {v}")


def main():
    debug = '--debug' in sys.argv
    args  = [a for a in sys.argv[1:] if not a.startswith('--')]
    if not args:
        sys.exit("Usage: python parse_ble.py <file.cfa> [--debug]")

    records = parse_btsnoop(args[0])
    print(f"Total records: {len(records)}\n")

    packets = list(iter_att(records, debug=debug))

    # --- discover handles from ReadByType responses ---
    handle_uuid = {}
    for from_remote, opcode, body in packets:
        if opcode != ATT_READ_BY_TYPE_RSP or not from_remote:
            continue
        if len(body) < 2:
            continue
        item_len = body[0]
        items = body[1:]
        while len(items) >= item_len:
            item, items = items[:item_len], items[item_len:]
            if len(item) < 2:
                break
            handle = struct.unpack('<H', item[:2])[0]
            ub = item[2:]
            if len(ub) == 2:
                uuid = f'{struct.unpack("<H", ub)[0]:04x}'
            elif len(ub) == 16:
                uuid = (f'{int.from_bytes(ub[12:16],"little"):08x}-'
                        f'{int.from_bytes(ub[10:12],"little"):04x}-'
                        f'{int.from_bytes(ub[8:10],"little"):04x}-'
                        f'{int.from_bytes(ub[6:8],"big"):04x}-'
                        f'{ub[:6].hex()}')
            else:
                uuid = ub.hex()
            handle_uuid[handle] = uuid

    known = {
        '81072f41': 'Notify-41 (motion?)',
        '81072f42': 'Notify-42 (EEG)',
        '81072f43': 'Cmd-43 (write/notify)',
        '81072f44': 'Read-44 (config)',
    }

    def label(handle):
        uuid = handle_uuid.get(handle, '')
        for prefix, name in known.items():
            if uuid.startswith(prefix):
                return f'h=0x{handle:04x} [{name}]'
        return f'h=0x{handle:04x} [{uuid or "?"}]'

    print("=== WRITES (host → headset) ===")
    writes = [(op, body) for from_remote, op, body in packets
              if op in (ATT_WRITE_REQ, ATT_WRITE_CMD) and not from_remote and len(body) >= 2]
    if not writes:
        print("  (none found)")
    for op, body in writes:
        handle = struct.unpack('<H', body[:2])[0]
        print(f"  {OPCODE_NAMES[op]} → {label(handle)}  {body[2:].hex()}")

    print("\n=== NOTIFICATIONS (headset → host) ===")
    notify_map = defaultdict(list)
    for from_remote, op, body in packets:
        if op in (ATT_NOTIFICATION, ATT_INDICATION) and from_remote and len(body) >= 2:
            handle = struct.unpack('<H', body[:2])[0]
            notify_map[handle].append(body[2:])

    if not notify_map:
        print("  (none found)")
    for handle, payloads in notify_map.items():
        print(f"\n  {label(handle)}  —  {len(payloads)} packets")
        for p in payloads[:5]:
            print(f"    {p.hex()}")
        if len(payloads) > 5:
            print(f"    ... ({len(payloads) - 5} more)")


if __name__ == '__main__':
    main()
