// CodeGuardian Frontend Logic

// This is your REAL API Gateway endpoint
const API_ENDPOINT = 'https://w1xos439ra.execute-api.us-east-1.amazonaws.com/analyze';

// Global state
let analysisRunning = false;

/**
 * Main function to start the analysis
 */
async function startAnalysis() {
    if (analysisRunning) return;
    
    analysisRunning = true;
    const btn = document.getElementById('analyzeBtn');
    const repoSelect = document.getElementById('repoSelect');
    
    // --- 1. Reset UI ---
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing...';
    
    document.getElementById('progressCard').classList.remove('hidden');
    document.getElementById('resultsCard').classList.add('hidden');
    document.getElementById('progressLog').innerHTML = ''; // Clear old logs
    
    updateStatus('running', '🤖 CodeGuardian agent is waking up...');
    
    try {
        const selectedRepo = repoSelect.value;
        
        // --- 2. Call the REAL API ---
        // We've removed the simulation logic to always call the real endpoint.
        // The catch block will handle any failures.
        await callRealAPI(selectedRepo);
        
        updateStatus('success', '✅ Analysis complete!');

    } catch (error) {
        console.error('Analysis Error:', error);
        updateStatus('error', `❌ Analysis failed: ${error.message}`);
        // Show a final error in the progress log
        addProgress('❌', 'Analysis Failed', error.message || 'Check browser console and Lambda logs for details.');
    } finally {
        // --- 4. Restore UI ---
        analysisRunning = false;
        btn.disabled = false;
        btn.innerHTML = '<span>🔍</span> Start Autonomous Analysis';
    }
}

/**
 * Calls the backend Lambda API and displays progress
 * @param {string} repository - The name of the repository to analyze
 */
async function callRealAPI(repository) {
    addProgress('🌐', 'Connecting to CodeGuardian API...', `Target: ${repository} repo`);
    
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
        // Try to parse the error message from Lambda, if any
        let errorBody = await response.text();
        try {
            const errorJson = JSON.parse(errorBody);
            if (errorJson && errorJson.error) {
                errorBody = errorJson.error;
            }
        } catch (e) { /* Not a JSON error, just use the text */ }
        
        throw new Error(`API request failed (${response.status}): ${errorBody}`);
    }
    
    const result = await response.json();
    
    if (!result.success) {
        throw new Error(result.error || 'API returned an unsuccessful status');
    }
    
    // --- 3. Display REAL Progress from the Lambda ---
    // This loops through the 'reasoning_chain' steps
    if (result.progress && result.progress.length > 0) {
        addProgress('🧠', 'Agent reasoning initiated...', 'Found steps in response');
        await sleep(500);
        for (const item of result.progress) {
            // Use the data from our lambda's 'format_results_for_frontend'
            addProgress(item.icon, item.text, item.subtext);
            await sleep(750); // A small delay to make the steps readable
        }
    }
    
    addProgress('📝', 'Agent finished reasoning', 'Compiling final report...');
    await sleep(1000);

    // Display REAL results
    displayResults(result);
}

/**
 * Updates the main status indicator
 * @param {'idle'|'running'|'success'|'error'} type - The status type
 * @param {string} message - The message to display
 */
function updateStatus(type, message) {
    const indicator = document.getElementById('statusIndicator');
    indicator.className = `status-indicator status-${type}`;
    
    let icon = '';
    if (type === 'running') icon = '<span class="spinner"></span>';
    if (type === 'idle') icon = '<span>💤</span>';
    if (type === 'success') icon = '<span>✅</span>';
    if (type === 'error') icon = '<span>❌</span>';
    
    indicator.innerHTML = `${icon} ${message}`;
}

/**
 * Adds a new item to the scrolling progress log
 * @param {string} icon - Emoji icon
 * @param {string} text - Main text
 * @param {string} subtext - Dimmer subtext
 */
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
    // Scroll to the bottom
    progressLog.scrollTop = progressLog.scrollHeight;
}

/**
 * Displays the final results in the Results Card
 * @param {object} result - The full JSON response from the Lambda
 */
function displayResults(result) {
    document.getElementById('resultsCard').classList.remove('hidden');
    
    // Update stats with REAL data
    document.getElementById('totalVulns').textContent = result.stats.total_vulnerabilities || 0;
    document.getElementById('toolsCalled').textContent = result.stats.tools_called || 0;
    document.getElementById('filesRead').textContent = result.stats.files_read || 0;
    document.getElementById('fixesGenerated').textContent = result.stats.fixes_generated || 0;
    
    // Display REAL vulnerabilities/issues
    const vulnContainer = document.getElementById('vulnerabilities');
    vulnContainer.innerHTML = ''; // Clear previous results
    
    if (!result.vulnerabilities || result.vulnerabilities.length === 0) {
        vulnContainer.innerHTML = '<p>No issues were found for this severity level.</p>';
        return;
    }

    result.vulnerabilities.forEach(vuln => {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.severity}`;
        
        // Use a template literal for cleaner HTML generation
        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">
                    ${vuln.title}
                    ${vuln.is_real ? '<span class="real-agent-badge">✨</span>' : ''}
                </div>
                <span class="severity-badge severity-${vuln.severity}">${vuln.severity}</span>
            </div>
            <p style="color: var(--color-text-dim); margin: 10px 0;">${vuln.description}</p>
            <div class="vuln-meta">
                <span>📄 ${vuln.file}:${vuln.line}</span>
                <span>🔖 ${vuln.cwe_id}</span>
            </div>
            
            <div style="margin-top: 20px;">
                <div class="code-label before">❌ Before (Identified Issue):</div>
                <div class="code-block-container">
                    <pre class="code-block"><code>${escapeHtml(vuln.before)}</code></pre>
                    <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
                </div>
            </div>
            
            <div class="fix-section">
                <div class="fix-title"><span>✅</span> Agent's Recommendation</div>
                <div class="code-label after">🚀 After (Modernized & Robust):</div>
                <div class="code-block-container">
                    <pre class="code-block"><code>${escapeHtml(vuln.after)}</code></pre>
                    <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
                </div>
                <p class="fix-reasoning">
                    <strong>🧠 Agent Reasoning:</strong> ${escapeHtml(vuln.reasoning)}
                </p>
            </div>
        `;
        vulnContainer.appendChild(card);
    });
    
    // Scroll to the results card
    document.getElementById('resultsCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Helper function to escape HTML special chars
 * @param {string} text - Text to escape
 */
function escapeHtml(text) {
    if (text === null || text === undefined) {
        return '';
    }
    const div = document.createElement('div');
    div.textContent = String(text); // Ensure it's a string
    return div.innerHTML;
}

/**
 * Helper function for async delays
 * @param {number} ms - Milliseconds to sleep
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Copies text from the sibling code block to the clipboard
 * @param {HTMLElement} button - The copy button that was clicked
 */
function copyToClipboard(button) {
    // Find the <pre> tag, which is the button's sibling's first child
    const preTag = button.previousElementSibling;
    if (preTag) {
        navigator.clipboard.writeText(preTag.textContent).then(() => {
            button.textContent = 'Copied!';
            button.style.background = 'var(--color-success)';
            setTimeout(() => {
                button.textContent = 'Copy';
                button.style.background = '';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            button.textContent = 'Error';
        });
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('CodeGuardian Dashboard Loaded');
    // You could add a 'test-connection' call here if you wanted
});