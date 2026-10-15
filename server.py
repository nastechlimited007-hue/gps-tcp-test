import asyncio
import json
import logging
import os
from datetime import datetime, timezone

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "7018"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("gt06-server")


def crc16_itu(data: bytes) -> int:
    """GT06 CRC-ITU: reflected polynomial 0x8408, init 0xFFFF, xorout 0xFFFF."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def packet_crc_ok(packet: bytes) -> bool:
    # GT06 packet: 78 78 LEN ... CRC_H CRC_L 0D 0A
    if len(packet) < 9 or packet[:2] != b"\x78\x78" or packet[-2:] != b"\x0d\x0a":
        return False
    expected = crc16_itu(packet[2:-4])
    received = int.from_bytes(packet[-4:-2], "big")
    return expected == received


def make_ack(protocol: int, serial: bytes) -> bytes:
    # Response format in the supplied CY05/CY06 GT06 protocol:
    # 78 78 05 <protocol> <serial:2> <CRC:2> 0D 0A
    body = bytes([0x05, protocol]) + serial
    crc = crc16_itu(body).to_bytes(2, "big")
    return b"\x78\x78" + body + crc + b"\x0d\x0a"


def decode_location(packet: bytes) -> dict:
    """
    Decode common GT06 GPS fields for protocols 0x12, 0x22, 0xA0 and 0x32.
    Protocol variants can add fields after the common GPS section; this intentionally
    extracts only the common timestamp/latitude/longitude/speed/course fields.
    """
    # packet indexes: 0-1 start, 2 length, 3 protocol, then 6-byte UTC timestamp
    if len(packet) < 22:
        return {"decode_error": "packet too short for common GPS fields"}

    yy, month, day, hour, minute, second = packet[4:10]
    gps_info = packet[10]
    lat_raw = int.from_bytes(packet[11:15], "big")
    lon_raw = int.from_bytes(packet[15:19], "big")
    speed_kmh = packet[19]
    course_status = int.from_bytes(packet[20:22], "big")

    # GT06 coordinate scale: decimal degrees = raw / 1,800,000.
    latitude = lat_raw / 1_800_000
    longitude = lon_raw / 1_800_000

    first_course_byte = packet[20]
    # Per the supplied protocol: bit 3 = longitude direction (0 east, 1 west);
    # bit 2 = latitude direction (1 north, 0 south).
    if first_course_byte & 0x08:
        longitude = -longitude
    if not (first_course_byte & 0x04):
        latitude = -latitude

    # Protocol examples use years as 2000 + YY. Timestamp is tracker UTC time.
    try:
        timestamp = datetime(
            2000 + yy, month, day, hour, minute, second, tzinfo=timezone.utc
        ).isoformat()
    except ValueError:
        timestamp = None

    return {
        "tracker_time_utc": timestamp,
        "latitude": round(latitude, 7),
        "longitude": round(longitude, 7),
        "speed_kmh": speed_kmh,
        "course_degrees": course_status & 0x03FF,
        "gps_info_byte_hex": f"0x{gps_info:02X}",
    }


def extract_packets(buffer: bytearray):
    """Yield complete 78 78 packets from a TCP byte stream."""
    packets = []
    while True:
        start = buffer.find(b"\x78\x78")
        if start < 0:
            # Keep one trailing byte in case it is the first byte of a split header.
            if buffer[-1:] == b"\x78":
                del buffer[:-1]
            else:
                buffer.clear()
            break
        if start:
            del buffer[:start]
        if len(buffer) < 3:
            break

        packet_length = buffer[2]
        total_length = packet_length + 5
        if packet_length < 5 or total_length > 1024:
            log.warning("Invalid packet length=%s; resynchronizing", packet_length)
            del buffer[0]
            continue
        if len(buffer) < total_length:
            break

        candidate = bytes(buffer[:total_length])
        if candidate[-2:] != b"\x0d\x0a":
            log.warning("Bad stop bytes; resynchronizing")
            del buffer[0]
            continue

        packets.append(candidate)
        del buffer[:total_length]
    return packets


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    log.info("TCP client connected: %s", peer)
    buffer = bytearray()

    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buffer.extend(chunk)

            for packet in extract_packets(buffer):
                protocol = packet[3]
                serial = packet[-6:-4]
                crc_ok = packet_crc_ok(packet)

                log.info(
                    "RX peer=%s bytes=%d protocol=0x%02X crc_ok=%s raw=%s",
                    peer, len(packet), protocol, crc_ok, packet.hex(" ").upper()
                )

                if not crc_ok:
                    log.warning("CRC check failed; no response sent")
                    continue

                if protocol == 0x01:
                    # Login: acknowledge to establish a normal session.
                    terminal_id = packet[4:12].hex().upper() if len(packet) >= 12 else "unknown"
                    log.info("GT06 login packet; terminal_id_bytes=%s serial=%s",
                             terminal_id, serial.hex().upper())
                    ack = make_ack(protocol, serial)
                    writer.write(ack)
                    await writer.drain()
                    log.info("TX login ACK: %s", ack.hex(" ").upper())

                elif protocol == 0x13:
                    # Heartbeat/status: acknowledge to keep the connection alive.
                    ack = make_ack(protocol, serial)
                    writer.write(ack)
                    await writer.drain()
                    log.info("TX heartbeat ACK: %s", ack.hex(" ").upper())

                elif protocol in (0x12, 0x22, 0xA0, 0x32):
                    # The supplied protocol says 0x22 location packets do not require a response.
                    log.info("GPS location: %s", json.dumps(decode_location(packet)))

                elif protocol in (0x16, 0x15, 0x1A):
                    log.info("Other GT06 packet protocol=0x%02X", protocol)

                else:
                    log.info("Unrecognized/extension protocol=0x%02X", protocol)

    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Client handler error for %s", peer)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info("TCP client disconnected: %s", peer)


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addresses = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    log.info("GT06 TCP server listening on %s", addresses)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
