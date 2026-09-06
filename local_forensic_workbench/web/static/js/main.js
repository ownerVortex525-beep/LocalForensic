// Local Forensic Data Correlation Workbench Client Scripts
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    return data;
  } catch (e) {
    console.error('Failed to load status', e);
  }
}

async function startScan(containerId = null, force = false) {
  const res = await fetch('/api/scan/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ container_id: containerId, force: force })
  });
  return await res.json();
}

async function stopScan() {
  const res = await fetch('/api/scan/stop', { method: 'POST' });
  return await res.json();
}
