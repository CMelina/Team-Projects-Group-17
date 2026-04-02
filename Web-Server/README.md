# Rebel Dissemination Hub: Metadata Decryption

## Overview
This server acts as the central node for receiving and displaying exfiltrated Imperial data. It integrates **XBee Serial communication** with a responsive web dashboard to provide real-time reconnaissance updates and secure message playback.

---

## Quick Start 

### 1. Clear Background Processes
For preventative measures, kill any lingering past processes on Port 3000: `sudo fuser -k 3000/tcp`

### 2. Launch the Server
Start the Node.js environment with `node server.js`

### 3. Access the Dashboard
Open Firefox and navigate to: `http://localhost:3000`

---

## Features & Credentials
| Feature | Logic | Credential |
| :--- | :--- | :--- |
| **Video Auth** | Swaps `Message2.mp4` to `Message1.mp4` | `REBEL_STRIKE_2026` |
| **Live Gallery** | Auto-polls `/api/list-images` every 3s | N/A (Automated) |
| **XBee Feed** | Listens on `/dev/ttyUSB0` (115200 baud) | N/A (Hardware) |

---

## Terminal Operations
To simulate a new data drop or re-run the decryption during the demo, use these exact commands from the terminal:

### 1. Verification of Encrypted Data
Check for incoming `.enc` files with `ls -l *.enc`

### 2. The Decryption Command
Use the decryption tool to move files into the gallery folder with `~/"Team Projects Web Server"/Team-Projects-Group-17/encryption-decryption/build/secure_transfer decrypt crops received_plans`

### 3. Live Log Monitoring
Open a second terminal tab to watch system events and XBee traffic with `tail -f system_logs.log`

---

## Troubleshooting
- If the gallery shows "SyntaxError" or "404," in the developer tools, the server is likely a ghost process. Run the `fuser` command in Step 1 and restart.
- If the XBee fails to initialize, ensure your user has dialout permissions: `  sudo chmod 666 /dev/ttyUSB0`

---

## Project Structure
* `server.js`: Node/Express backend & RFC 5424 Logger.
* `app.js`: Frontend logic (auth, video swapping, gallery polling).
* `received_plans/`: Storage for decrypted `.png` assets (gallery source).
* `Message1.mp4` / `Message2.mp4`: Local briefing files.
