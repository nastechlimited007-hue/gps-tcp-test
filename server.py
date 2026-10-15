

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

