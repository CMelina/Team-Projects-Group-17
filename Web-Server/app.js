/**
 * Web Server and Authentication Handling
 */

// 1. RFC 5424 log formatting
function rfc5424Log(severity, msg) {
    const facility = 1; // user messages
    const PRI = (facility * 8) + severity;
    const timestamp = new Date().toISOString();
    const logEntry = `<${PRI}>1 ${timestamp} rebel-server web-ui - - - ${msg}`;
    
    document.getElementById('syslog-display').innerText = logEntry;
    console.log(logEntry);
}

// 2. audio access logic authentication test; subject to change
async function fetchR2Audio(token = null) {
    const headers = {};
    if (token) {
        headers['x-api-key'] = token;
    }

    try {
        rfc5424Log(6, "REQUESTING_AUDIO_STREAM");
        const response = await fetch('/api/message', { headers });
        
        if (!response.ok) throw new Error("Auth Failed");

        const blob = await response.blob();
        document.getElementById('r2-audio-player').src = URL.createObjectURL(blob);
        
        if (token) {
            document.getElementById('auth-section').innerHTML = "<p style='color:var(--rebel-green)'>✓ FULL ACCESS GRANTED</p>";
            document.getElementById('dl-btn').disabled = false;
            rfc5424Log(5, "FULL_MESSAGE_DECRYPTED_SUCCESS");
        } else {
            rfc5424Log(6, "PARTIAL_MESSAGE_LOADED");
        }
    } catch (e) {
        rfc5424Log(4, "UNAUTHORIZED_OR_CONNECTION_ERROR");
    }
}

function authenticateR2() {
    const key = document.getElementById('api-token-input').value;
    fetchR2Audio(key);
}

// 3. populate table
function updatePlanTable(plans) {
    const tableBody = document.getElementById('plans-table-body');
    tableBody.innerHTML = "";

    plans.forEach(plan => {
        const row = `<tr>
            <td>${plan.id}</td>
            <td><div class="target-circle"></div></td>
            <td class="${plan.valid ? 'severity critical' : 'warning-text'}">
                ${plan.md5} [${plan.valid ? 'OK' : 'FAIL'}]
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });
    
    document.getElementById('plan-count').innerText = plans.length;
}

// simulated data for UI testing
    fetchR2Audio(); {
    updatePlanTable([]); // empty array for now
};