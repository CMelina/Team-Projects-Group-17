import hashlib
import struct
import time
from pathlib import Path

import serial

# Serial config
PORT = "/dev/ttyUSB0"
BAUD = 115200

# Folder containing files to send
SOURCE_FOLDER = "crops"

# Chunk size for sending
CHUNK_SIZE = 256

# Hardware flow control
USE_RTSCTS = True

# ACK responses expected from receiver
ACK_OK = b"OK"
ACK_RETRY = b"NO"


# Reads exactly n bytes from serial
def read_exact(ser: serial.Serial, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if not chunk:
            continue
        data += chunk
    return data


# Sends bytes reliably
def send_exact(ser: serial.Serial, data: bytes) -> None:
    ser.write(data)
    ser.flush()


# Computes MD5 checksum of a file
def md5_file(path: Path) -> bytes:
    h = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()  # returns raw 16-byte MD5


# Sends a single file
def send_one_file(ser: serial.Serial, file_path: Path) -> None:
    filename_bytes = file_path.name.encode("utf-8")
    file_size = file_path.stat().st_size
    file_md5 = md5_file(file_path)

    # Ensure filename fits in 2 bytes
    if len(filename_bytes) > 65535:
        raise ValueError(f"Filename too long: {file_path.name}")

    # Send filename length + filename
    send_exact(ser, struct.pack(">H", len(filename_bytes)))
    send_exact(ser, filename_bytes)

    # Send file size (8 bytes)
    send_exact(ser, struct.pack(">Q", file_size))

    # Send file data in chunks
    sent = 0
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            send_exact(ser, chunk)
            sent += len(chunk)
            print(f"\r  sent {sent}/{file_size} bytes", end="", flush=True)

    # Send checksum after file data
    send_exact(ser, file_md5)
    print("\n  md5 sent:", file_md5.hex())


# Waits for receiver response (OK or NO)
def wait_for_status(ser: serial.Serial) -> bytes:
    return read_exact(ser, 2)


def main() -> None:
    source_dir = Path(SOURCE_FOLDER)

    # Validate source directory
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source folder not found: {source_dir}")

    # Collect files to send
    files = sorted([p for p in source_dir.iterdir() if p.is_file()])

    if not files:
        print("No files found to send.")
        return

    # Open serial connection
    ser = serial.Serial(PORT, BAUD, timeout=1, rtscts=USE_RTSCTS)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    # Give XBee time to stabilize
    time.sleep(2)

    # Send total number of files first
    send_exact(ser, struct.pack(">I", len(files)))
    print(f"Sending {len(files)} file(s)...")

    # Send each file
    for index, file_path in enumerate(files, start=1):
        print(f"\nFile {index}/{len(files)}: {file_path.name}")

        attempt = 1
        while True:
            print(f"Attempt {attempt}")

            send_one_file(ser, file_path)

            status = wait_for_status(ser)

            if status == ACK_OK:
                print("  receiver verified MD5: OK")
                break

            elif status == ACK_RETRY:
                print("  receiver reported MD5 mismatch, resending...")

            else:
                print(f"  unexpected response: {status!r}, resending...")

            attempt += 1

    print("\nAll files sent successfully.")
    ser.close()


if __name__ == "__main__":
    main()