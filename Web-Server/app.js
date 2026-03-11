let player;
let fullAccess = false;

// Load YouTube API
const tag = document.createElement('script');
tag.src = "https://www.youtube.com/iframe_api";
document.head.appendChild(tag);

async function loadVideo(token = null) {
    const headers = token ? { 'x-api-key': token } : {};
    try {
        const response = await fetch('/api/video-config', { headers });
        const config = await response.json();
        fullAccess = config.isFullAccess;

        if (player) {
            player.loadVideoById(config.videoId);
        } else {
            player = new YT.Player('r2-video-player', {
                height: '240', width: '100%', videoId: config.videoId,
                events: { 'onStateChange': onPlayerStateChange }
            });
        }
        if (fullAccess) {
            document.getElementById('auth-section').innerHTML = "<p style='color:#2ecc71'>✓ ACCESS GRANTED</p>";
        }
    } catch (e) { console.error("Video Auth Error", e); }
}

function onPlayerStateChange(event) {
    if (!fullAccess && event.data == YT.PlayerState.PLAYING) {
        const timer = setInterval(() => {
            if (player.getCurrentTime() >= (player.getDuration() / 2)) {
                player.pauseVideo();
                alert("Remainder of message is encrypted.");
                clearInterval(timer);
            }
        }, 1000);
    }
}

function authenticateR2() {
    const key = document.getElementById('api-token-input').value;
    loadVideo(key);
}

window.onYouTubeIframeAPIReady = () => loadVideo();
