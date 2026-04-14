let fullAccess = false;
const API_KEY = "REBEL_STRIKE_2026";

async function checkAuth() {
    const tokenInput = document.getElementById('api-token').value;
    const authBox = document.querySelector('.auth-box');

    if (tokenInput === API_KEY) {
        // overwrite the HTML to show the 2FA UI
        authBox.innerHTML = `
            <div id="2fa-area" style="text-align:center;">
                <p style="color:#00d2ff; font-size: 14px; margin-bottom: 10px;">STEP 2: SCAN AUTHENTICATOR</p>
                <img id="qr-image" style="background:white; padding:10px; border-radius:5px; width:150px; display:block; margin: 0 auto;">
                <input type="text" id="2fa-code" placeholder="Enter 6-digit code" style="display:block; width:80%; margin:15px auto; text-align:center;">
                <button onclick="confirm2FA()" class="rebel-btn" style="width:100%;">VALIDATE ACCESS</button>
            </div>
        `;

        setTimeout(() => {
            const secret = "JBSWY3DPEHPK3PXP";
            const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=otpauth://totp/RebelStrike?secret=${secret}%26issuer=RebelHub`;
            
            const imgElement = document.getElementById('qr-image');
            if (imgElement) {
                imgElement.src = qrUrl;
                console.log("QR Code source set successfully.");
            }
        }, 50);

    } else {
        alert("Invalid Token. Access Denied.");
    }
}

function confirm2FA() {
    const code = document.getElementById('2fa-code').value;
    
    // 123456 is master code for logic testing purposes
    if (code === "123456") {
        fullAccess = true;
        const video = document.getElementById('rebel-video');
        const videoSource = document.getElementById('video-source');
        const status = document.getElementById('access-level');

        videoSource.src = "Message1.mp4";
        video.load(); 
        status.innerText = "ACCESS GRANTED: 2FA VERIFIED";
        status.style.color = "#2ecc71";
        video.play();
        
        document.getElementById('2fa-area').style.display = 'none';
    } else {
        alert("Invalid 2FA Code. Use 123456 for the demo.");
    }
}

// message 2 playback
const video = document.getElementById('rebel-video');
if (video) {
    video.ontimeupdate = function() {
        // if they have not authed and try to watch more than half of message 2
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
