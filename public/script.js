const API_URL = '/api';

// DOM Elements
const hostInput = document.getElementById('hostInput');
const checkBtn = document.getElementById('checkBtn');
const resultsTableBody = document.querySelector('#resultsTable tbody');
const tabs = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const statusMessage = document.getElementById('statusMessage');
const downloadJsonBtn = document.getElementById('downloadJsonBtn');
const downloadcsvBtn = document.getElementById('downloadCsvBtn');
const refreshBtn = document.getElementById('refreshBtn');
const clearBtn = document.getElementById('clearBtn');

let currentData = [];

// Event Listeners
checkBtn.addEventListener('click', handleSingleCheck);
refreshBtn.addEventListener('click', loadResults);
clearBtn.addEventListener('click', clearResults);
downloadJsonBtn.addEventListener('click', downloadJson);
downloadCsvBtn.addEventListener('click', downloadCsv);

// Tabs Logic
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
    });
});

// File Upload Logic
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', handleFileDrop);
fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));

// Initial Load
loadResults();

// Logic
async function handleSingleCheck() {
    const hostname = hostInput.value.trim();
    if (!hostname) return;

    setLoading(true);
    setStatus('Checking ' + hostname + '...');

    try {
        const res = await fetch(`${API_URL}/check-host`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hostname })
        });

        if (!res.ok) throw new Error('Check failed');

        const data = await res.json();
        // Reload table to show updated status
        await loadResults();
        setStatus(`Checked ${hostname} successfully.`);
        hostInput.value = '';
    } catch (err) {
        setStatus(`Error: ${err.message}`);
    } finally {
        setLoading(false);
    }
}

function handleFileDrop(e) {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    handleFile(file);
}

function handleFile(file) {
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
        const text = e.target.result;
        const hostnames = text.split('\n').map(l => l.trim()).filter(l => l);

        if (hostnames.length === 0) {
            setStatus('No valid hostnames found.');
            return;
        }

        setStatus(`Queueing ${hostnames.length} hosts...`);
        // Process in batches or one by one? 
        // For simplicity, one by one but sequential to avoid rate limits
        setLoading(true);
        let successCount = 0;

        for (const host of hostnames) {
            try {
                setStatus(`Checking ${host}... (${successCount + 1}/${hostnames.length})`);
                await fetch(`${API_URL}/check-host`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hostname: host })
                });
                successCount++;
            } catch (err) {
                console.error(`Failed to check ${host}`, err);
            }
        }

        setLoading(false);
        setStatus(`Completed. Checked ${successCount}/${hostnames.length} hosts.`);
        loadResults();
    };
    reader.readAsText(file);
}

async function loadResults() {
    try {
        const res = await fetch(`${API_URL}/results`);
        if (res.ok) {
            currentData = await res.json();
            renderTable(currentData);
        }
    } catch (err) {
        console.error('Failed to load results', err);
    }
}

async function clearResults() {
    if (!confirm('Are you sure you want to delete all records? This cannot be undone.')) return;

    setLoading(true);
    setStatus('Clearing records...');

    try {
        const res = await fetch(`${API_URL}/results`, { method: 'DELETE' });
        if (res.ok) {
            setStatus('All records cleared.');
            loadResults();
        } else {
            throw new Error('Failed to clear records');
        }
    } catch (err) {
        setStatus(`Error: ${err.message}`);
    } finally {
        setLoading(false);
    }
}

function renderTable(data) {
    resultsTableBody.innerHTML = '';

    if (data.length === 0) {
        resultsTableBody.innerHTML = '<tr><td colspan="9" style="text-align:center">No data found</td></tr>';
        return;
    }

    data.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${row.hostname}</td>
            <td>${truncate(row.authoritative_ns || '')}</td>
            <td>${renderBadge(row.is_proxied, 'yes')}</td>
            <td>${row.dns_type || '-'}</td>
            <td>${truncate(row.dns_result || '')}</td>
            <td>${renderBadge(row.ssl_google, 'allowed')}</td>
            <td>${renderBadge(row.ssl_ssl_com, 'allowed')}</td>
            <td>${renderBadge(row.ssl_lets_encrypt, 'allowed')}</td>
        `;
        resultsTableBody.appendChild(tr);
    });
}

function renderBadge(value, goodVal) {
    if (!value) return '-';
    let className = 'badge ' + value;
    return `<span class="${className}">${value.replace('_', ' ')}</span>`;
}

function renderZoneHoldBadge(value) {
    if (!value) return '-';
    // Logic: 
    // - 'yes' = red (confirmed zone hold via API)
    // - 'likely' = yellow/orange (CF nameservers detected, likely on another account)
    // - 'no' = green (not on Cloudflare or no hold detected)
    let className = 'badge';
    if (value === 'yes') className += ' not_allowed'; // Red - confirmed hold
    if (value === 'likely') className += ' zone-hold-likely'; // Yellow - likely hold
    if (value === 'no') className += ' allowed';      // Green - no hold

    const displayText = value === 'likely' ? 'Likely Hold' : value;
    return `<span class="${className}">${displayText}</span>`;
}

function truncate(str, len = 30) {
    if (typeof str !== 'string') return str;
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function setLoading(isLoading) {
    checkBtn.disabled = isLoading;
    const loader = checkBtn.querySelector('.loader');
    const text = checkBtn.querySelector('.btn-text');

    if (isLoading) {
        loader.classList.remove('hidden');
        text.style.opacity = '0'; // Hide text but keep width
    } else {
        loader.classList.add('hidden');
        text.style.opacity = '1';
    }
}

function setStatus(msg) {
    statusMessage.textContent = msg;
}

function downloadJson() {
    const blob = new Blob([JSON.stringify(currentData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'hostname-check-results.json';
    a.click();
}

function downloadCsv() {
    if (currentData.length === 0) return;

    const headers = Object.keys(currentData[0]);
    const csvRows = [];

    // Header
    csvRows.push(headers.join(','));

    // Rows
    for (const row of currentData) {
        const values = headers.map(header => {
            const val = row[header] || '';
            const escaped = ('' + val).replace(/"/g, '""');
            return `"${escaped}"`;
        });
        csvRows.push(values.join(','));
    }

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'hostname-check-results.csv';
    a.click();
}
