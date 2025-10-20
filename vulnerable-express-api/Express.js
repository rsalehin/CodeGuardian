const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const app = express();

app.use(express.json());

// VULNERABILITY 1: CORS Misconfiguration
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});

// VULNERABILITY 2: Command Injection
app.post('/api/ping', (req, res) => {
    const host = req.body.host;
    
    // Vulnerable: Direct command execution with user input
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        res.json({ output: stdout });
    });
});

// VULNERABILITY 3: Path Traversal
app.get('/api/files/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // Vulnerable: No path validation
    const filepath = `./uploads/${filename}`;
    const content = fs.readFileSync(filepath, 'utf8');
    
    res.send(content);
});

// VULNERABILITY 4: Prototype Pollution
app.post('/api/settings', (req, res) => {
    const settings = req.body;
    
    // Vulnerable: Allows __proto__ pollution
    function merge(target, source) {
        for (let key in source) {
            target[key] = source[key];
        }
    }
    
    const config = {};
    merge(config, settings);
    
    res.json({ updated: true });
});

// VULNERABILITY 5: Insecure Deserialization
app.post('/api/import', (req, res) => {
    const data = req.body.data;
    
    // Vulnerable: eval() on user input
    const imported = eval(`(${data})`);
    
    res.json({ imported: true });
});

// VULNERABILITY 6: Hardcoded Credentials
const DB_PASSWORD = 'admin123';
const API_KEY = 'sk-1234567890abcdef';

// VULNERABILITY 7: Information Disclosure
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack  // Exposes stack trace
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});