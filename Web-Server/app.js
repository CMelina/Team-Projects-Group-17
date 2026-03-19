async function checkAuth() {
    const tokenInput = document.getElementById('api-token').value;
    const videoPlayer = document.getElementById('rebel-video');
    const videoSource = document.getElementById('video-source');
    const statusText = document.getElementById('access-level');

    try {
        const response = await fetch('/authenticate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: tokenInput })
        });

        const result = await response.json();

        if (result.success) {
            // Update UI
            statusText.innerText = "AUTHENTICATED (FULL ACCESS)";
            statusText.style.color = "#ffff00";

            // Change video source to full message
            videoSource.src = "Message1.mp4";
            
            // Force reload and play
            videoPlayer.load();
            videoPlayer.play();
            
            alert("Identity Verified. Accessing Restricted Holo-data.");
        } else {
            alert("Authentication Failed. Access Denied.");
        }
    } catch (error) {
        console.error("Connection Error:", error);
        alert("Could not connect to Rebel Server.");
    }
}
