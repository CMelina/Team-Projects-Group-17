const express = require('express');
const app = express();
const path = require('path');
const { SerialPort } = require('serialport');
const fs = require('fs');

// Configs
const PORT = 3000;
const SERIAL_PATH = '/dev/ttyUSB0'; // Linux path
const API_TOKEN = "REBEL_BASE_2026"; // Hardcoded key

// Middleware
app.use(express.json()); // For reading the API token
app.use(express.static(__dirname)); // Serves index, app.js, and videos

// Serial hardware setup
const serialPort = new SerialPort({ path: SERIAL_PATH, baudRate: 9600 }, (err) => {
    if (err) return console.log('Serial Port Error (Check XBee connection):', err.message);
    console.log(`Serial Port opened on ${SERIAL_PATH}`);
});

// Authentication endpoint
app.post('/authenticate', (req, res) => {
    const { token } = req.body;
    
    // log the attempt to system_logs.log (RFC 5424 simplified)
    const logEntry = `<134>1 ${new Date().toISOString()} Puter RebelHub - AUTH_ATTEMPT - Token: ${token}\n`;
    fs.appendFileSync('system_logs.log', logEntry);

    if (token === API_TOKEN) {
        console.log("Access Granted: Valid Token.");
        res.json({ success: true });
    } else {
        console.log("Access Denied: Invalid Token.");
        res.json({ success: false });
    }
});

// Server initialization
app.listen(PORT, () => {
    console.log(`Rebel Hub online at http://localhost:${PORT}`);
    console.log(`Defaulting to Message2.mp4 (Restricted)`);
});
