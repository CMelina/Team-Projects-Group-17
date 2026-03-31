const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const PORT = 3000;
const API_KEY = "REBEL_STRIKE_2026"; 
const LOG_FILE = 'system_logs.log';
const UPLOAD_DIR = path.join(__dirname, 'received_plans');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

app.use(express.json());
// Raw parser to handle binary image data from XBee
app.use(express.raw({ type: 'image/jpeg', limit: '10mb' }));
app.use(express.static(__dirname));

function writeRFC5424(severity, msgId, message) {
    const PRI = (1 * 8) + severity;
    const logEntry = `<${PRI}>1 ${new Date().toISOString()} rebel-base-laptop rebel-server ${process.pid} ${msgId} - ${message}\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
    console.log(logEntry);
}

// Actual image upload handler
app.post('/api/upload-plan', (req, res) => {
    const hardwareToken = req.headers['x-api-key'];
    if (hardwareToken !== API_KEY) {
        writeRFC5424(3, "XFER_FAIL", "Unauthorized hardware attempt.");
        return res.status(401).send("Unauthorized");
    }

    const filename = `plan_${Date.now()}.jpg`;
    const filePath = path.join(UPLOAD_DIR, filename);

    fs.writeFile(filePath, req.body, (err) => {
        if (err) {
            writeRFC5424(3, "WRITE_ERR", "Failed to save image.");
            return res.status(500).send("Error saving file");
        }
        writeRFC5424(5, "XFER_SUCCESS", `New plan saved: ${filename}`);
        res.status(200).send({ status: "Verified", file: filename });
    });
});

// Endpoint for the UI to get the list of images
app.get('/api/plans', (req, res) => {
    fs.readdir(UPLOAD_DIR, (err, files) => {
        if (err) return res.status(500).send("Error reading plans");
        const planData = files.map((file, index) => ({
            id: index + 1,
            md5: file, // Using filename as placeholder for MD5
            valid: true
        }));
        res.json(planData);
    });
});

app.get('/api/message', (req, res) => {
    const userKey = req.headers['x-api-key'];
    const file = (userKey === API_KEY) ? 'full_r2.mp3' : 'partial_r2.mp3';
    res.sendFile(path.join(__dirname, 'audio', file));
});

app.listen(PORT, () => {
    writeRFC5424(6, "SYS_START", `Rebel Server active on local port ${PORT}`);
});
