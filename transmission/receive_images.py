import hashlib
import struct
from pathlib import Path

import serial

# Serial configuration
PORT = "/dev/ttyUSB0"
BAUD = 115200

# Where received files will be saved
DEST_FOLDER = "crops"

# Size of chunks to read at a time
CHUNK_SIZE = 256

# Hardware flow control (RTS/CTS)
USE_RTSCTS = True

# Acknowledgement messages sent back to sender
ACK_OK = b"OK"      # File received correctly
ACK_RETRY = b"NO"   # File corrupted, resend


# Reads exactly n bytes from serial (blocking until complete)
def read_exact(ser: serial.Serial, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if not chunk:
            continue  # keep waiting if nothing received
        data += chunk
    return data


# Sends all bytes and ensures they are flushed out
def send_exact(ser: serial.Serial, data: bytes) -> None:
    ser.write(data)
    ser.flush()


# Prevents directory traversal
def safe_filename(name: str) -> str:
    return Path(name).name


# Receives a single file from sender
def receive_one_file(ser: serial.Serial, dest_dir: Path) -> bool:
    # Read filename length (2 bytes)
    name_len = struct.unpack(">H", read_exact(ser, 2))[0]

    # Read filename
    filename = read_exact(ser, name_len).decode("utf-8")
    filename = safe_filename(filename)

    # Read file size (8 bytes)
    file_size = struct.unpack(">Q", read_exact(ser, 8))[0]

    output_path = dest_dir / filename

    print(f"Receiving: {filename} ({file_size} bytes)")

    md5_calc = hashlib.md5()  # Used to compute checksum while receiving
    received = 0

    # Open file for writing binary data
    with output_path.open("wb") as f:
        while received < file_size:
            # Read next chunk
            chunk = read_exact(ser, min(CHUNK_SIZE, file_size - received))
            f.write(chunk)

            # Update checksum
            md5_calc.update(chunk)

            received += len(chunk)
            print(f"\r  received {received}/{file_size} bytes", end="", flush=True)

    print()

    # Read expected MD5 from sender (16 bytes)
    expected_md5 = read_exact(ser, 16)
    actual_md5 = md5_calc.digest()

    print("  expected md5:", expected_md5.hex())
    print("  actual   md5:", actual_md5.hex())

    # Compare checksums
    if actual_md5 == expected_md5:
        send_exact(ser, ACK_OK)  # Acknowledge successful
        print("  md5 match, sent OK")
        return True

    # If corrupted, delete file and request resend
    output_path.unlink(missing_ok=True)
    send_exact(ser, ACK_RETRY)
    print("  md5 mismatch, sent NO and deleted file")
    return False


def main() -> None:
    # Create destination directory if it doesn't exist
    dest_dir = Path(DEST_FOLDER)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Open serial connection
    ser = serial.Serial(PORT, BAUD, timeout=1, rtscts=USE_RTSCTS)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    print("Waiting for folder transfer...")

    # First 4 bytes = number of files
    file_count = struct.unpack(">I", read_exact(ser, 4))[0]
    print(f"Expecting {file_count} file(s).")

    completed = 0
    current_index = 1

    # Keep receiving until all files are successfully transferred
    while completed < file_count:
        print(f"\nFile {current_index}/{file_count}")

        ok = receive_one_file(ser, dest_dir)

        if ok:
            completed += 1
            current_index += 1
        else:
            print("  waiting for resend of same file...")

    print("\nAll files received successfully.")
    ser.close()


if __name__ == "__main__":
    main()