// Tab Switching
function openTab(tabName, event) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    event.currentTarget.classList.add('active');
}

// Map Initialization
document.addEventListener('DOMContentLoaded', function () {
    const map = L.map('map', { center: [20, 0], zoom: 2, worldCopyJump: true });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap'
    }).addTo(map);

    const userMarker = L.circleMarker([12.9716, 77.5946], {
        color: '#00ffff',
        radius: 7,
        fillOpacity: 0.8
    }).addTo(map).bindPopup("Your Location");

    const alertsContainer = document.getElementById('alerts');
    const logsContainer = document.getElementById('logs');
    const blockedContainer = document.getElementById('blocked');
    const statusDisplay = document.getElementById('status-display');

    // Fetch system status
    async function fetchStatus() {
        try {
            const res = await fetch('/status');
            const data = await res.json();
            if (data.mode === 'Learning') {
                statusDisplay.innerHTML = `Status: <span class="learning">Learning... (${data.time_remaining}s)</span>`;
            } else {
                statusDisplay.innerHTML = `Status: <span class="monitoring">Monitoring</span>`;
            }
        } catch {
            statusDisplay.innerHTML = 'Status: <span class="learning">Error</span>';
        }
    }

    // Fetch traffic data
    async function fetchTraffic() {
        try {
            const res = await fetch('/traffic');
            const data = await res.json();
            data.forEach(item => {
                drawConnection(item);
                addLogEntry(item);
            });
        } catch (err) {
            console.error('Traffic fetch error:', err);
        }
    }

    // Fetch blocked IPs
    async function fetchBlocked() {
        try {
            const res = await fetch('/blocked');
            const blocked = await res.json();
            blockedContainer.innerHTML = '';
            blocked.forEach(ip => {
                const div = document.createElement('div');
                div.classList.add('log-entry', 'blocked-entry');
                div.innerHTML = `<b>${ip}</b> has been blocked 🔒`;
                blockedContainer.appendChild(div);
            });
        } catch (err) {
            console.error('Blocked fetch error:', err);
        }
    }

    // Draw animated path
    function drawConnection(connection) {
        if (!connection.lat || !connection.lon) return;
        const color = connection.score >= 0.6 ? '#ff4444' : '#00ff99';
        const line = L.curve(['M', [12.9716, 77.5946], 'Q', [20, 40], [connection.lat, connection.lon]], {
            color,
            weight: 2,
            opacity: 0.7
        }).addTo(map);
        setTimeout(() => map.removeLayer(line), 2000);
    }

    // Log Entry Creation
    function addLogEntry(connection) {
        const div = document.createElement('div');
        const risk = connection.score >= 0.6 ? 'high-risk' : 'low-risk';
        div.classList.add('log-entry', risk);
        div.innerHTML = `
            <div>${connection.src_ip} → ${connection.dst_ip}</div>
            <div>${connection.country} (${connection.external_ip}) <span class="log-score">${connection.score}</span></div>
        `;
        if (risk === 'high-risk') {
            alertsContainer.prepend(div);
            if (alertsContainer.children.length > 40) alertsContainer.removeChild(alertsContainer.lastChild);
        } else {
            logsContainer.prepend(div);
            if (logsContainer.children.length > 50) logsContainer.removeChild(logsContainer.lastChild);
        }
    }

    // Timers
    setInterval(fetchStatus, 2000);
    setInterval(fetchTraffic, 1500);
    setInterval(fetchBlocked, 4000);
});
