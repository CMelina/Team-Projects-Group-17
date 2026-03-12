const videoPlayer = document.getElementById('rebel-video');
const videoSource = document.getElementById('video-source');
const accessLevel = document.getElementById('access-level');

async function checkAuth() {
    const tokenInput = document.getElementById('api-token').value;

    try {
        const response = await fetch('/authenticate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: tokenInput })
        });

        const result = await response.json();

        if (result.success) {
            // update UI
            accessLevel.innerText = "AUTHENTICATED (FULL)";
            accessLevel.style.color = "#ffff00";
            
            // swap the video source to the full message
            videoSource.src = "Message1.mp4";
            
            // reload the player to recognize the new source
            videoPlayer.load();
            videoPlayer.play();
            
            alert("Identity Verified. Playing Full Message.");
        } else {
            alert("Authentication Failed: Invalid Token.");
        }
    } catch (error) {
        console.error("Auth Error:", error);
        alert("Server Connection Error.");
    }
}

// function to poll for incoming plans (SerialPort bridge)
function updatePlansTable() {
    fetch('/get-latest-plans')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById('table-body');
            // populate table rows
        });
}

// check for new plans every 5 seconds
setInterval(updatePlansTable, 5000);
