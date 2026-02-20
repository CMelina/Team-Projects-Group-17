const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// config
const PORT = 3000;
const API_KEY = "REBEL_STRIKE_2026"; 
const LOG_FILE = 'system_logs.log';

// ensures upload directory exists
const UPLOAD_DIR = path.join(__dirname, 'received_plans');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// for parsing JSON for MD5/SHA-256 exchange
app.use(express.json());
app.use(express.static(__dirname));

/**
 * RFC 5424 Logging Logic
 * <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
 */
function writeRFC5424(severity, msgId, message) {
    const PRI = (1 * 8) + severity; // User-level facility
    const VERSION = "1";
    const TIMESTAMP = new Date().toISOString();
    const HOSTNAME = "rebel-base-laptop";
    const APP_NAME = "rebel-server";
    const PROCID = process.pid;

    const logEntry = `<${PRI}>${VERSION} ${TIMESTAMP} ${HOSTNAME} ${APP_NAME} ${PROCID} ${msgId} - ${message}\n`;
    
    // append-only Log
    fs.appendFileSync(LOG_FILE, logEntry);
    console.log(logEntry);
}

/**
 * Integration point; image upload
 * This is where the decrypted images will hypothetically be posted
 */
app.post('/api/upload-plan', (req, res) => {
    // checks if the transmitter has the correct session key/auth
    const hardwareToken = req.headers['x-api-key'];
    
    if (hardwareToken === API_KEY) {
        // logic placeholder; subject to change
        writeRFC5424(5, "XFER_SUCCESS", "New plan image verified and saved.");
        res.status(200).send({ status: "Verified" });
    } else {
        writeRFC5424(3, "XFER_FAIL", "Unauthorized hardware transmission attempt.");
        res.status(401).send("Unauthorized");
    }
});

/**
 * auth: audio message access
 */
app.get('/api/message', (req, res) => {
    const userKey = req.headers['x-api-key'];

    if (userKey === API_KEY) {
        writeRFC5424(5, "AUTH_SUCCESS", "Authenticated user access: Full R2 message.");
        res.sendFile(path.join(__dirname, 'audio', 'full_r2.mp3'));
    } else {
        writeRFC5424(6, "AUTH_PUBLIC", "Public user access: Partial R2 message.");
        res.sendFile(path.join(__dirname, 'audio', 'partial_r2.mp3'));
    }
});

app.listen(PORT, () => {
    writeRFC5424(6, "SYS_START", `Rebel Server active on port ${PORT}`);
});