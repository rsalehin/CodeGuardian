// CodeGuardian Frontend Logic

const API_ENDPOINT = 'API_GATEWAY_URL_HERE';

let analysisRunning = false;
let progressItems = [];

async function startAnalysis() {
    if (analysisRunning) return;
    
    analysisRunning = true;
    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.textContent = '🔄 Analyzing...';
    
    document.getElementById('progressCard').classList.remove('hidden');
    document.getElementById('resultsCard').classList.add('hidden');
    
    updateStatus('running', '🤖 CodeGuardian agent is analyzing...');
    
    progressItems = [];
    document.getElementById('progressLog').innerHTML = '';
    
    try {
        await simulateAnalysis();
        updateStatus('success', '✅ Analysis complete!');
    } catch (error) {
        updateStatus('error', '❌ Analysis failed: ' + error.message);
    } finally {
        analysisRunning = false;
        btn.disabled = false;
        btn.textContent = '🔍 Start Autonomous Analysis';
    }
}

async function simulateAnalysis() {
    await addProgress('🔍', 'Agent decided: "I need to scan for vulnerabilities"', 'Calling scan_repository tool...');
    await sleep(2000);
    await addProgress('✅', 'scan_repository completed', 'Found 23 HIGH severity vulnerabilities');
    
    await sleep(1500);
    await addProgress('🧠', 'Agent reasoning: "I need context to generate accurate fixes"', 'Calling read_file_content tool...');
    await sleep(2000);
    await addProgress('✅', 'read_file_content completed (3 files)', 'Retrieved full context including imports and dependencies');
    
    await sleep(1500);
    await addProgress('🔧', 'Agent decided: "I should validate my fix proposals"', 'Calling validate_python_syntax tool...');
    await sleep(2000);
    await addProgress('✅', 'validate_python_syntax completed (3 fixes)', 'All proposed fixes are syntactically valid');
    
    await sleep(1500);
    await addProgress('📝', 'Agent decided: "Task complete, generating report"', 'Compiling recommendations...');
    await sleep(1000);
    
    displayResults();
}

async function addProgress(icon, text, subtext) {
    const progressLog = document.getElementById('progressLog');
    const item = document.createElement('div');
    item.className = 'progress-item';
    item.innerHTML = `
        <div class="progress-icon">${icon}</div>
        <div class="progress-text">
            <div>${text}</div>
            <div class="progress-time">${subtext}</div>
        </div>
    `;
    progressLog.appendChild(item);
    progressLog.scrollTop = progressLog.scrollHeight;
}

function updateStatus(type, message) {
    const indicator = document.getElementById('statusIndicator');
    indicator.className = `status-indicator status-${type}`;
    
    let icon = '';
    if (type === 'running') icon = '<span class="spinner"></span>';
    
    indicator.innerHTML = icon + message;
}

function displayResults() {
    document.getElementById('resultsCard').classList.remove('hidden');
    
    document.getElementById('totalVulns').textContent = '23';
    document.getElementById('toolsCalled').textContent = '7';
    document.getElementById('filesRead').textContent = '3';
    document.getElementById('fixesGenerated').textContent = '3';
    
    const vulns = [
        {
            title: 'SQL Injection in Login Function',
            severity: 'high',
            file: 'app.py',
            line: 42,
            description: 'User input directly concatenated into SQL query without sanitization.',
            before: `query = f"SELECT * FROM users WHERE username='{username}'"`,
            after: `query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))`,
            reasoning: 'Agent analyzed the code and determined that sqlite3 is being used. Recommended parameterized queries with ? placeholders specific to sqlite3.'
        },
        {
            title: 'Hardcoded Secret Key',
            severity: 'high',
            file: 'app.py',
            line: 8,
            description: 'Flask secret key hardcoded in source code.',
            before: `app.secret_key = 'super_secret_key_12345'`,
            after: `import os
app.secret_key = os.getenv('SECRET_KEY')`,
            reasoning: 'Agent identified configuration management issue and recommended environment variable usage.'
        },
        {
            title: 'Debug Mode in Production',
            severity: 'medium',
            file: 'app.py',
            line: 76,
            description: 'Flask app running with debug=True exposes debugger.',
            before: `app.run(debug=True, host='0.0.0.0')`,
            after: `debug = os.getenv('FLASK_DEBUG', 'False') == 'True'
app.run(debug=debug, host='0.0.0.0')`,
            reasoning: 'Agent recommended environment-based configuration to prevent debug mode in production.'
        }
    ];
    
    const vulnContainer = document.getElementById('vulnerabilities');
    vulnContainer.innerHTML = '';
    
    vulns.forEach(vuln => {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.severity}`;
        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">${vuln.title}</div>
                <span class="severity-badge severity-${vuln.severity}">${vuln.severity}</span>
            </div>
            <p style="color: #666; margin-bottom: 10px;">${vuln.description}</p>
            <p style="font-size: 0.9em; color: #999;">📄 ${vuln.file}:${vuln.line}</p>
            
            <div style="margin-top: 15px;">
                <strong>❌ Before (Vulnerable):</strong>
                <div class="code-block">${vuln.before}</div>
            </div>
            
            <div class="fix-section">
                <div class="fix-title">✅ Agent's Recommendation:</div>
                <div class="code-block">${vuln.after}</div>
                <p style="margin-top: 10px; font-size: 0.9em; color: #555;">
                    <strong>🧠 Agent Reasoning:</strong> ${vuln.reasoning}
                </p>
            </div>
        `;
        vulnContainer.appendChild(card);
    });
    
    vulnContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('CodeGuardian Dashboard Loaded');
});