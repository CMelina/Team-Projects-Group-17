#  Rebel Dissemination Hub - Web Server Setup

This folder contains the Node.js Rebel Server responsible for the "Obi-Wan Kenobi" authentication test, RFC 5424 logging, and the real-time display of exfiltrated Death Star plans.

##  Prerequisites

Before starting, ensure your system has the following installed:
- Node.js (v16 or higher)
- npm (Node Package Manager)
- XBee Modules (connected via USB)

---

##  Installation & Launch

Follow these steps in order to start the server on your local machine:

### 1. Install Dependencies
Open terminal in this folder and run:
```bash
npm install
```
*Note: This downloads the necessary libraries (`express`, `serialport`) listed in the `package.json`.*

### 2. Configure Hardware Path

Open `server.js` and ensure the serial path is set to the Linux USB port (since `COM3` is for Windows):

```
// Ensure this matches XBee device name
const port = new SerialPort({ path: '/dev/ttyUSB0', baudRate: 9600 });
```

### 3. Start the Server

Run the launch command:

```
node server.js
```

The console should display: `Server listening on http://localhost:3000`.

---

## Mission Operations & Logic

### The "Obi-Wan Kenobi Message" Authentication Test

The server handles the restricted dissemination of the R2-D2 holographic data:

- Public Access (Default): The HUD loads `Message2.mp4` (a 50% partial version of the secret message).
- Elevated Access: Entering the correct API Token triggers a frontend swap to `Message1.mp4` (the full mission message).

### Data Integrity (The Death Star Plans)

- Storage: The C++ decryption module must save the 10 exfiltrated images to the `/received_plans` folder.
- Display: The web interface polls the server and updates the scrollable table with filenames and verification statuses.

### RFC 5424 Logging

All system events (authentication success/fail, XBee packet arrival, image verification) are appended to `system_logs.log` using the RFC 5424 standard:

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
```
---

## Project Structure

| File | Description |
| --- | --- |
| `server.js` | Express backend, API routes, and SerialPort listener. |
| `app.js` | Frontend HUD logic and video source swapping. |
| `index.html` | Undercover web interface structure. |
| `style.css` | Glassmorphism/Terminal styling for the Rebel UI. |
| `Message1.mp4` | Unrestricted Full Message (The Full Reveal). |
| `Message2.mp4` | Restricted Partial Message (The 50% Teaser). |
| `received_plans/` | Landing directory for decrypted exfiltration data. |
| `system_logs.log` | RFC 5424 Append-Only Log. |

---

## Troubleshooting

- SerialPort Error: If the server crashes on startup, run `ls /dev/tty*` in your terminal to find the correct path for your XBee and update it in `server.js`.
- Video Not Loading: Ensure both `.mp4` files are in the same directory as `index.html`.
- Git Rejection: If you cannot push, run `git pull origin main --rebase` first to sync with teammate changes.
