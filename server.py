
import socket
import threading

HOST = "0.0.0.0"
PORT = 7018

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"From {addr}: {data.hex(' ')}")
            print(f"Text: {data!r}")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        conn.close()
        print(f"Disconnected: {addr}")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

print(f"TCP test server listening on {HOST}:{PORT}")

while True:
    conn, addr = server.accept()
    threading.Thread(
        target=handle_client,
        args=(conn, addr),
        daemon=True
    ).start()
