const { invoke } = window.__TAURI__.core;

let pidInput;
let statusText;
let protectedPidsList;
let logView;

const logLines = [];
const maxLogLines = 2000;

function appendLog(message) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logView.appendChild(entry);

  logLines.push(entry);
  if (logLines.length > maxLogLines) {
    const removed = logLines.shift();
    removed.remove();
  }

  logView.scrollTop = logView.scrollHeight;
}

function updateStatus(connected) {
  if (connected) {
    statusText.textContent = 'Connected';
    statusText.className = 'status-connected';
  } else {
    statusText.textContent = 'Disconnected';
    statusText.className = 'status-disconnected';
  }
}

async function updateProtectedPids() {
  try {
    const pids = await invoke("get_protected_pids");
    if (pids.length === 0) {
      protectedPidsList.textContent = 'None';
    } else {
      protectedPidsList.textContent = pids.join(', ');
    }
  } catch (error) {
    appendLog(`Error updating PIDs: ${error}`);
  }
}

async function addPid() {
  const pid = parseInt(pidInput.value);
  if (isNaN(pid)) {
    appendLog('Invalid PID');
    return;
  }

  try {
    const result = await invoke("add_protected_pid", { pid });
    appendLog(result);
    await updateProtectedPids();
  } catch (error) {
    appendLog(`Add PID failed: ${error}`);
  }
}

async function removePid() {
  const pid = parseInt(pidInput.value);
  if (isNaN(pid)) {
    appendLog('Invalid PID');
    return;
  }

  try {
    const result = await invoke("remove_protected_pid", { pid });
    appendLog(result);
    await updateProtectedPids();
  } catch (error) {
    appendLog(`Remove PID failed: ${error}`);
  }
}

async function clearAllPids() {
  try {
    const result = await invoke("clear_all_pids");
    appendLog(result);
    await updateProtectedPids();
  } catch (error) {
    appendLog(`Clear all PIDs failed: ${error}`);
  }
}

async function setPpl() {
  const pid = parseInt(pidInput.value);
  if (isNaN(pid)) {
    appendLog('Invalid PID');
    return;
  }

  try {
    const result = await invoke("set_ppl", { pid });
    appendLog(result);
  } catch (error) {
    appendLog(`Set PPL failed: ${error}`);
  }
}

async function scanBlacklist() {
  appendLog('[Blacklist] Starting scan...');
  try {
    const matches = await invoke("scan_blacklist", { keywords: null });

    if (matches.length > 0) {
      appendLog(`[Blacklist] Found ${matches.length} suspicious process(es):`);
      matches.forEach(match => {
        appendLog(`[Blacklist] PID ${match.pid}: ${match.path} (matched: ${match.keyword})`);
      });
    } else {
      appendLog('[Blacklist] No blacklisted processes found');
    }
  } catch (error) {
    appendLog(`[Blacklist] Scan failed: ${error}`);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  pidInput = document.querySelector("#pid-input");
  statusText = document.querySelector("#status-text");
  protectedPidsList = document.querySelector("#protected-pids-list");
  logView = document.querySelector("#log-view");

  document.querySelector("#add-btn").addEventListener("click", addPid);
  document.querySelector("#remove-btn").addEventListener("click", removePid);
  document.querySelector("#clear-btn").addEventListener("click", clearAllPids);
  document.querySelector("#ppl-btn").addEventListener("click", setPpl);
  document.querySelector("#scan-btn").addEventListener("click", scanBlacklist);

  // Try to connect to kernel driver
  invoke("connect_to_kernel")
    .then(result => {
      appendLog(result);
      updateStatus(true);
      updateProtectedPids();
    })
    .catch(error => {
      appendLog(`Connection failed: ${error}`);
      updateStatus(false);
    });

  appendLog('Peregrine Monitor started');
});
