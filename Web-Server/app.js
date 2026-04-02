let fullAccess = false;
const API_KEY = "REBEL_STRIKE_2026";

// Authentication and video Swap
async function checkAuth() {
    const tokenInput = document.getElementById('api-token').value;
    const video = document.getElementById('rebel-video');
    const videoSource = document.getElementById('video-source');
    const status = document.getElementById('access-level');

    if (tokenInput === API_KEY) {
        fullAccess = true;
        
        // Change source to Message 1
        videoSource.src = "Message1.mp4";
        
        // Call .load() after changing the src
        video.load(); 
        
        status.innerText = "ACCESS GRANTED: MESSAGE 1 UNLOCKED";
        status.style.color = "#2ecc71";
        
        video.play(); // Auto-start the new message
    } else {
        alert("Invalid Token. Access Denied.");
    }
}

// Restricted playback for Message 2
const video = document.getElementById('rebel-video');
if (video) {
    video.ontimeupdate = function() {
        // If they haven't authed and try to watch more than half of Message 2
        if (!fullAccess && video.currentTime > (video.duration / 2)) {
            video.pause();
            video.currentTime = video.duration / 2;
            alert("Further data is encrypted. Enter API Token to unlock Message 1.");
        }
    };
}

// Image gallery logic
async function refreshImageGallery() {
    try {
        const response = await fetch('/api/list-images');
        const images = await response.json();
        const gallery = document.getElementById('image-gallery');

        if (images && images.length > 0) {
            gallery.innerHTML = images.map(img => `
                <div class="recon-item" style="display: inline-block; margin: 10px; text-align: center;">
                    <img src="/plans/${img}" class="recon-thumb" 
                         style="width: 120px; height: 120px; object-fit: cover; border: 1px solid #00d2ff;"
                         onclick="window.open(this.src)">
                    <div style="font-size: 10px; color: #2ecc71; margin-top: 5px;">${img}</div>
                </div>
            `).join('');
        }
    } catch (e) {
        console.error("Gallery Sync Error:", e);
    }
}

// Start gallery loop
refreshImageGallery();
setInterval(refreshImageGallery, 3000);
