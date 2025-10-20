// CodeGuardian Frontend Logic

// const API_ENDPOINT = 'API_GATEWAY_URL_HERE'; // Will update after Lambda deployment
// For local SAM testing
const API_ENDPOINT = 'https://ri3u7f8y7b.execute-api.us-east-1.amazonaws.com/analyze';
let analysisRunning = false;
let progressItems = [];

async function startAnalysis() {
    if (analysisRunning) return;
    
    analysisRunning = true;
    const btn = document.getElementById('analyzeBtn');
    const repoSelect = document.getElementById('repoSelect');
    
    btn.disabled = true;
    btn.textContent = '🔄 Analyzing...';
    
    document.getElementById('progressCard').classList.remove('hidden');
    document.getElementById('resultsCard').classList.add('hidden');
    
    updateStatus('running', '🤖 CodeGuardian agent is analyzing...');
    
    progressItems = [];
    document.getElementById('progressLog').innerHTML = '';
    
    try {
        const selectedRepo = repoSelect.value;
        
        // If API_ENDPOINT is configured, call real API
        if (API_ENDPOINT && API_ENDPOINT !== 'API_GATEWAY_URL_HERE') {
            await callRealAPI(selectedRepo);
        } else {
            // Fallback to simulation
            await simulateAnalysis();
        }
        
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
    // Step 1: Scanning
    await addProgress('🔍', 'Agent decided: \"I need to scan for vulnerabilities\"', 'Calling scan_repository tool...');
    await sleep(2000);
    await addProgress('✅', 'scan_repository completed', 'Found 23 HIGH severity vulnerabilities');
    
    // Step 2: Reading files
    await sleep(1500);
    await addProgress('🧠', 'Agent reasoning: \"I need context to generate accurate fixes\"', 'Calling read_file_content tool...');
    await sleep(2000);
    await addProgress('✅', 'read_file_content completed (3 files)', 'Retrieved full context including imports and dependencies');
    
    // Step 3: Generating fixes
    await sleep(1500);
    await addProgress('🔧', 'Agent decided: \"I should validate my fix proposals\"', 'Calling validate_python_syntax tool...');
    await sleep(2000);
    await addProgress('✅', 'validate_python_syntax completed (3 fixes)', 'All proposed fixes are syntactically valid');
    
    // Step 4: Final recommendations
    await sleep(1500);
    await addProgress('📝', 'Agent decided: \"Task complete, generating report\"', 'Compiling recommendations...');
    await sleep(1000);
    
    // Show results
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
async function callRealAPI(repository) {
    // Call REAL Lambda API
    addProgress('🌐', 'Connecting to CodeGuardian API...', 'Initializing analysis');
    
    const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            repository: repository
        })
    });
    
    if (!response.ok) {
        throw new Error('API request failed: ' + response.statusText);
    }
    
    const result = await response.json();
    
    if (!result.success) {
        throw new Error(result.error || 'Analysis failed');
    }
    
    // Display REAL progress
    if (result.progress && result.progress.length > 0) {
        for (const item of result.progress) {
            await addProgress(item.icon, item.text, item.subtext);
            await sleep(800);
        }
    }
    
    // Display REAL results
    displayRealResults(result);
}


function updateStatus(type, message) {
    const indicator = document.getElementById('statusIndicator');
    indicator.className = `status-indicator status-${type}`;
    
    let icon = '';
    if (type === 'running') icon = '<span class="spinner"></span>';
    
    indicator.innerHTML = icon + message;
}
function displayRealResults(result) {
    document.getElementById('resultsCard').classList.remove('hidden');
    
    // Update stats with REAL data
    document.getElementById('totalVulns').textContent = result.stats.total_vulnerabilities;
    document.getElementById('toolsCalled').textContent = result.stats.tools_called;
    document.getElementById('filesRead').textContent = result.stats.files_read;
    document.getElementById('fixesGenerated').textContent = result.stats.fixes_generated;
    
    // Display REAL vulnerabilities
    const vulnContainer = document.getElementById('vulnerabilities');
    vulnContainer.innerHTML = '';
    
    result.vulnerabilities.forEach(vuln => {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.severity}`;
        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">${vuln.title} ${vuln.is_real ? '✨ REAL AGENT' : ''}</div>
                <span class="severity-badge severity-${vuln.severity}">${vuln.severity}</span>
            </div>
            <p style="color: #666; margin-bottom: 10px;">${vuln.description}</p>
            <p style="font-size: 0.9em; color: #999;">📄 ${vuln.file}:${vuln.line}</p>
            <p style="font-size: 0.85em; color: #2196F3;">🔖 ${vuln.cwe_id}</p>
            
            <div style="margin-top: 15px;">
                <strong>❌ Before (Vulnerable):</strong>
                <div class="code-block">${escapeHtml(vuln.before)}</div>
            </div>
            
            <div class="fix-section">
                <div class="fix-title">✅ Agent's Recommendation:</div>
                <div class="code-block">${escapeHtml(vuln.after)}</div>
                <p style="margin-top: 10px; font-size: 0.9em; color: #555;">
                    <strong>🧠 Agent Reasoning:</strong> ${vuln.reasoning}
                </p>
            </div>
        `;
        vulnContainer.appendChild(card);
    });
    
    vulnContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


function displayResults() {
    document.getElementById('resultsCard').classList.remove('hidden');
    
    // Update stats
    document.getElementById('totalVulns').textContent = '23';
    document.getElementById('toolsCalled').textContent = '7';
    document.getElementById('filesRead').textContent = '3';
    document.getElementById('fixesGenerated').textContent = '3';
    
    // Sample vulnerabilities
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
    card.className = 'vulnerability-card';
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

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('CodeGuardian Dashboard Loaded');
});

