const express = require('express');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const API_KEY = "REBEL_STRIKE_2026"; // specified token
const LOG_FILE = 'system_logs.log';

// Xbee serial setup
const port = new SerialPort({ path: '/dev/ttyUSB0', baudRate: 9600 });
const parser = port.pipe(new ReadlineParser({ delimiter: '\r\n' }));

// RFC 5424 logger function
function writeRFC5424(severity, msgId, message) {
    const PRI = (1 * 8) + severity;
    const logEntry = `<${PRI}>1 ${new Date().toISOString()} rebel-laptop rebel-server ${process.pid} ${msgId} - ${message}\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
    console.log(logEntry);
}

// Serve static frontend files
app.use(express.static(__dirname));
app.use('/plans', express.static(path.join(__dirname, 'received_plans')));

// Endpoint for YouTube Config
app.get('/api/video-config', (req, res) => {
    const userKey = req.headers['x-api-key'];
    res.json({
        videoId: "dQw4w9WgXcQ", // Replace with actual R2 message ID
        isFullAccess: (userKey === API_KEY)
    });
});

// XBee Listener: Receives data from pyserial script
parser.on('data', (data) => {
    writeRFC5424(6, "XBEE_RECEIVE", `Incoming data: ${data}`);
    // Note: Parse 'data' to update plan list
});

app.listen(PORT, () => {
    if (!fs.existsSync('./received_plans')) fs.mkdirSync('./received_plans');
    writeRFC5424(6, "SYS_START", `Server active on http://localhost:${PORT}`);
});