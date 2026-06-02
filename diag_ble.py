import asyncio
from bleak import BleakClient

# Known address from Windows Device Manager
DEVICE_ADDRESS = "FB:38:12:E0:C3:38"
# Emotiv custom service found in Windows PnP
EMOTIV_SERVICE = "81072f40-9f3d-11e3-a9dc-0002a5d5c51b"

notifications = []

def handle_notify(char, data: bytearray):
    notifications.append((char, bytes(data)))
    print(f"  NOTIFY [{char}] ({len(data)}B): {bytes(data).hex()}")

async def main():
    from bleak import BleakScanner
    print(f"Looking for {DEVICE_ADDRESS} (up to 15s) ...")
    device = await BleakScanner.find_device_by_address(DEVICE_ADDRESS, timeout=15.0)
    if device is None:
        print("Device not found — make sure headset is on and not connected to another app.")
        return
    print(f"Found: {device.name}")

    print("Connecting ...")
    async with BleakClient(device) as client:
        print(f"Connected: {client.is_connected}\n")

        for svc in client.services:
            print(f"Service {svc.uuid}  —  {svc.description}")
            for char in svc.characteristics:
                props = ",".join(char.properties)
                print(f"  Char {char.uuid}  [{props}]")
                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char.uuid)
                        print(f"    value: {bytes(val).hex()}  {bytes(val)!r}")
                    except Exception as e:
                        print(f"    read error: {e}")

        # Subscribe to all notifiable characteristics and listen 10s
        print("\n--- subscribing to all notify/indicate characteristics ---")
        for svc in client.services:
            for char in svc.characteristics:
                if "notify" in char.properties or "indicate" in char.properties:
                    try:
                        await client.start_notify(char.uuid,
                            lambda h, d, c=char.uuid: handle_notify(c, d))
                        print(f"  subscribed: {char.uuid}")
                    except Exception as e:
                        print(f"  subscribe failed {char.uuid}: {e}")

        print("\nListening for 10 seconds ...")
        await asyncio.sleep(10)

        if not notifications:
            print("No notifications received.")
        else:
            print(f"\nReceived {len(notifications)} notifications total.")

asyncio.run(main())
