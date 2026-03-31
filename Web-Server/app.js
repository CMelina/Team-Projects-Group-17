function rfc5424Log(severity, msg) {
    const PRI = (1 * 8) + severity;
    const logEntry = `<${PRI}>1 ${new Date().toISOString()} rebel-server web-ui - - - ${msg}`;
    const display = document.getElementById('syslog-display');
    if(display) display.innerText = logEntry;
    console.log(logEntry);
}

async function fetchR2Audio(token = null) {
    const headers = {};
    if (token) headers['x-api-key'] = token;

    try {
        rfc5424Log(6, "REQUESTING_AUDIO_STREAM");
        const response = await fetch('/api/message', { headers });
        if (!response.ok) throw new Error("Auth Failed");

        const blob = await response.blob();
        document.getElementById('r2-audio-player').src = URL.createObjectURL(blob);
        
        if (token) {
            document.getElementById('auth-section').innerHTML = "<p style='color:#2ecc71'>✓ FULL ACCESS GRANTED</p>";
            document.getElementById('dl-btn').disabled = false;
            rfc5424Log(5, "FULL_MESSAGE_DECRYPTED_SUCCESS");
        }
    } catch (e) {
        rfc5424Log(4, "UNAUTHORIZED_OR_CONNECTION_ERROR");
    }
}

function authenticateR2() {
    const key = document.getElementById('api-token-input').value;
    fetchR2Audio(key);
}

function updatePlanTable(plans) {
    const tableBody = document.getElementById('plans-table-body');
    tableBody.innerHTML = plans.map(plan => `
        <tr>
            <td>${plan.id}</td>
            <td><div class="target-circle"></div></td>
            <td class="${plan.valid ? 'severity critical' : 'warning-text'}">
                ${plan.md5} [${plan.valid ? 'OK' : 'FAIL'}]
            </td>
        </tr>
    `).join('');
    
    document.getElementById('plan-count').innerText = plans.length;
}

// Function to check server for new plans
async function refreshPlans() {
    try {
        const response = await fetch('/api/plans');
        const plans = await response.json();
        updatePlanTable(plans);
    } catch (err) {
        console.error("Failed to refresh plans");
    }
}

// Initialization
window.onload = () => {
    fetchR2Audio();
    refreshPlans();
    // Refresh the table every 5 seconds to see new XBee uploads
    setInterval(refreshPlans, 5000);
};
