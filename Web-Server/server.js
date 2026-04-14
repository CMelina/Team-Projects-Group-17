const express = require('express');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const LOG_FILE = 'system_logs.log';

// static folders
app.use(express.static(__dirname));
app.use('/plans', express.static(path.join(__dirname, 'received_plans')));

app.get('/api/list-images', (req, res) => {
    const imagesPath = path.join(__dirname, 'received_plans');
    
    if (!fs.existsSync(imagesPath)) {
        return res.json([]);
    }

    fs.readdir(imagesPath, (err, files) => {
        if (err) return res.status(500).json([]);
        const images = files.filter(file => /\.(png|jpg|jpeg|gif|webp)$/i.test(file));
        res.json(images);
    });
});

app.listen(PORT, () => {
    console.log(`Server active on http://localhost:${PORT}`);
});
