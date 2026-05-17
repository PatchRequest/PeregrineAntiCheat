<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";

  type LogEntry = { id: number; text: string; tag: string; ts: string };
  let nextId = 0;

  let status = $state("Disconnected");
  let statusColor = $state("#c83c3c");
  let connected = $state(false);
  let pidInput = $state("");
  let targetInput = $state("");
  let protectedPids = $state<number[]>([]);
  let injectionTargets = $state<string[]>([]);
  let logs = $state<LogEntry[]>([]);
  let logEl: HTMLDivElement;
  const MAX_LOGS = 2000;

  const tagColors: Record<string, string> = {
    ok: "#4ec94e", tamper: "#ff4444", suspicious: "#ff3333",
    remote_thr: "#ff6644", handle: "#e8a838", imgload: "#6ab0f3",
    thr_ok: "#4ec94e", blacklist: "#e67e22", drv_bl: "#ff4444",
    drv_scan: "#6ab0f3", obcb: "#e8a838", syschk: "#a78bfa",
    iat_hook: "#ff4444", eat_hook: "#ff4444", ppl: "#4a90e2",
    inj_fail: "#ff4444", apc_ok: "#4ec94e", apc_fail: "#ff4444",
    conn: "#4ec94e", err: "#c83c3c", info: "#6ab0f3",
    default: "#cdd6f4",
  };

  function now() {
    return new Date().toLocaleTimeString("de-DE", { hour12: false });
  }

  function addLog(text: string, tag = "default") {
    logs = [...logs.slice(-(MAX_LOGS - 1)), { id: nextId++, text, tag, ts: now() }];
    requestAnimationFrame(() => logEl?.scrollTo(0, logEl.scrollHeight));
  }

  function tagFor(ev: any): string {
    const s = ev.status ?? ev.event ?? "";
    if (s === "success") return "apc_ok";
    if (s === "failed") return "apc_fail";
    return "info";
  }

  async function connect() {
    try {
      const msg: string = await invoke("connect_driver");
      status = "Connected";
      statusColor = "#4ec94e";
      connected = true;
      addLog(msg, "conn");
    } catch (e: any) {
      status = "Disconnected";
      statusColor = "#c83c3c";
      connected = false;
      addLog(`connect failed: ${e}`, "err");
    }
  }

  async function addTarget() {
    const name = targetInput.trim();
    if (!name) { addLog("target name is empty", "err"); return; }
    if (!requireDriver()) return;
    try {
      const msg: string = await invoke("add_injection_target", { name });
      injectionTargets = [...injectionTargets, name];
      addLog(`[APC] ${msg}`, "apc_ok");
      targetInput = "";
    } catch (e: any) {
      addLog(`[APC] add target failed: ${e}`, "err");
    }
  }

  async function clearTargets() {
    if (!requireDriver()) return;
    try {
      const msg: string = await invoke("clear_injection_targets");
      injectionTargets = [];
      addLog(`[APC] ${msg}`, "info");
    } catch (e: any) {
      addLog(`[APC] clear failed: ${e}`, "err");
    }
  }

  function requirePid(): number | null {
    const pid = parseInt(pidInput, 10);
    if (isNaN(pid) || pidInput.trim() === "") {
      addLog("PID input is empty", "err");
      return null;
    }
    return pid;
  }

  function requireDriver(): boolean {
    if (!connected) {
      addLog("not connected to driver", "err");
      return false;
    }
    return true;
  }

  async function addPid() {
    const pid = requirePid();
    if (pid === null) return;
    if (!requireDriver()) return;
    try {
      await invoke("add_pid", { pid });
      protectedPids = [...protectedPids, pid];
      addLog(`added PID ${pid}`, "ok");
    } catch (e: any) {
      addLog(`add_pid failed: ${e}`, "err");
    }
  }
  async function removePid() {
    const pid = requirePid();
    if (pid === null) return;
    if (!requireDriver()) return;
    try {
      await invoke("remove_pid", { pid });
      protectedPids = protectedPids.filter(p => p !== pid);
      addLog(`removed PID ${pid}`, "ok");
    } catch (e: any) {
      addLog(`remove_pid failed: ${e}`, "err");
    }
  }
  async function clearAll() {
    if (!requireDriver()) return;
    try {
      await invoke("clear_pids");
      protectedPids = [];
      addLog("cleared all PIDs", "ok");
    } catch (e: any) {
      addLog(`clear_pids failed: ${e}`, "err");
    }
  }
  async function setPpl() {
    const pid = requirePid();
    if (pid === null) return;
    if (!requireDriver()) return;
    try {
      await invoke("set_ppl", { pid });
      addLog(`[PPL] set PID ${pid}`, "ppl");
    } catch (e: any) {
      addLog(`set_ppl failed: ${e}`, "err");
    }
  }

  async function checkModules() {
    const pid = requirePid();
    if (pid === null) return;
    addLog(`[Module Check] Checking modules for PID ${pid}...`, "info");
    try {
      const res: any[] = await invoke("check_modules", { pid });
      for (const r of res) {
        const tag = r.matched === true ? "ok" : r.matched === false ? "tamper" : "info";
        const label = r.matched === true ? "ok" : r.matched === false ? "tamper" : "?";
        addLog(`[${label}] ${r.path} matched=${r.matched} ${r.mem_sha256?.slice(0,8) ?? ""} ${r.error ?? ""}`, tag);
      }
      addLog(`[Module Check] Done. ${res.length} modules checked`, "info");
    } catch (e: any) { addLog(`module check failed: ${e}`, "err"); }
  }

  async function checkIat() {
    const pid = requirePid();
    if (pid === null) return;
    addLog(`[IAT Scan] Scanning PID ${pid}...`, "info");
    try {
      const res: any[] = await invoke("check_iat", { pid });
      if (res.length) {
        addLog(`[IAT Hook] Found ${res.length} hook(s)`, "iat_hook");
        for (const h of res) addLog(`[IAT Hook] ${h.module} -> ${h.imported_dll}!${h.function} IAT=0x${h.iat_value.toString(16).toUpperCase()}`, "iat_hook");
      } else {
        addLog(`[IAT Scan] PID ${pid}: No hooks detected`, "ok");
      }
    } catch (e: any) { addLog(`IAT scan failed: ${e}`, "err"); }
  }

  async function checkEat() {
    const pid = requirePid();
    if (pid === null) return;
    addLog(`[EAT Scan] Scanning PID ${pid}...`, "info");
    try {
      const res: any[] = await invoke("check_eat", { pid });
      if (res.length) {
        addLog(`[EAT Hook] Found ${res.length} hook(s)`, "eat_hook");
        for (const h of res) addLog(`[EAT Hook] ${h.module}!${h.function} RVA=0x${h.rva.toString(16)} -> 0x${h.target_addr.toString(16).toUpperCase()}`, "eat_hook");
      } else {
        addLog(`[EAT Scan] PID ${pid}: No hooks detected`, "ok");
      }
    } catch (e: any) { addLog(`EAT scan failed: ${e}`, "err"); }
  }

  async function checkThreads() {
    const pid = requirePid();
    if (pid === null) return;
    addLog(`[Thread Scan] Checking PID ${pid}...`, "info");
    try {
      const res: any[] = await invoke("check_threads", { pid });
      let sus = 0;
      for (const t of res) {
        if (t.suspicious) {
          sus++;
          const ripMod = t.rip_module ?? "UNKNOWN";
          const startMod = t.start_module ?? "UNKNOWN";
          const startHex = t.start_address ? `0x${t.start_address.toString(16).toUpperCase()}` : "?";
          addLog(`[SUSPICIOUS THREAD ${t.tid}] RIP=0x${t.rip.toString(16).toUpperCase()} (${ripMod}) Start=${startHex} (${startMod})`, "suspicious");
        }
      }
      addLog(`[Thread Scan] ${res.length} threads, ${sus} suspicious`, "info");
    } catch (e: any) { addLog(`thread scan failed: ${e}`, "err"); }
  }

  async function scanBlacklist() {
    addLog("[Blacklist] Scanning...", "info");
    try {
      const res: any[] = await invoke("scan_blacklist");
      if (res.length) {
        for (const m of res) addLog(`[Blacklist] PID ${m.pid}: ${m.path} (${m.keyword})`, "blacklist");
      } else {
        addLog("[Blacklist] No matches found", "ok");
      }
    } catch (e: any) { addLog(`blacklist scan failed: ${e}`, "err"); }
  }

  let etwRunning = $state(false);

  async function startEtwTi() {
    if (etwRunning) { addLog("[ETW-TI] already running", "info"); return; }
    if (!requireDriver()) return;
    addLog("[ETW-TI] Setting PPL and starting trace...", "info");
    try {
      const msg: string = await invoke("start_etw_ti");
      etwRunning = true;
      addLog(`[ETW-TI] ${msg}`, "apc_ok");
    } catch (e: any) {
      addLog(`[ETW-TI] failed: ${e}`, "err");
    }
  }

  function handleEtwTiEvent(d: any) {
    if (!d) return;
    const t = d.event_type ?? "?";
    const prot = d.protection ? `0x${d.protection.toString(16)}` : "";

    const tag = t.includes("REMOTE") ? "suspicious" : "info";
    addLog(`[ETW-TI] ${t} | PID ${d.caller_pid} → ${d.target_pid} | 0x${(d.base_address ?? 0).toString(16).toUpperCase()} size=0x${(d.region_size ?? 0).toString(16)} ${prot}`, tag);
  }

  async function driverCmd(name: string) {
    if (!requireDriver()) return;
    try {
      await invoke(name);
      addLog(`[${name}] command sent`, "info");
    } catch (e: any) {
      addLog(`${name} failed: ${e}`, "err");
    }
  }

  const ACCESS_FLAGS: Record<number, string> = {
    0x0001: "TERMINATE", 0x0002: "CREATE_THREAD",
    0x0008: "VM_OPERATION", 0x0010: "VM_READ",
    0x0020: "VM_WRITE", 0x0040: "DUP_HANDLE",
    0x0800: "SUSPEND_RESUME",
  };
  const DANGEROUS = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800;

  function handleDriverEvent(d: any) {
    if (!d) return;
    const event = d.event ?? "";

    switch (event) {
      case "process_create":
      case "process_exit":
      case "thread_create":
      case "thread_exit":
        break;

      case "file_access":
        addLog(`[File Access] PID=${d.pid} op=${d.op} ${d.path}`, "handle");
        break;


      case "image_load":
        addLog(`[Image Load] PID=${d.pid} ${d.image ?? "?"}`, "imgload");
        break;

      case "ob_callback": {
        const raw = d.desired_access ?? "0x0";
        const access = typeof raw === "string" ? parseInt(raw, 16) : raw;
        if (access & DANGEROUS) {
          const flags = Object.entries(ACCESS_FLAGS)
            .filter(([bit]) => access & Number(bit))
            .map(([, name]) => name)
            .join("|");
          addLog(`[Handle Access] PID=${d.caller_pid} -> PID=${d.target_pid} op=${d.op} [${flags}]`, "handle");
        }
        break;
      }

      case "apc_inject":
        if (d.status === "success") {
          addLog(`[ok] APC injection PID=${d.pid} TID=${d.tid}`, "apc_ok");
          protectedPids = [...protectedPids, d.pid];
        } else {
          addLog(`[DLL Inject FAIL] APC injection PID=${d.pid} error=${d.error}`, "apc_fail");
        }
        break;

      case "driver_scan":
        addLog(`[Driver Blacklist] DETECTED: ${d.driver} (${d.path}) size=${d.size}`, "drv_bl");
        break;

      case "driver_scan_complete": {
        const bl = d.blacklisted_count ?? 0;
        if (bl > 0)
          addLog(`[Driver Scan] Complete: ${d.total_drivers} drivers loaded, ${bl} BLACKLISTED`, "drv_scan");
        else
          addLog(`[Driver Scan] Complete: ${d.total_drivers} drivers loaded, none blacklisted`, "drv_scan");
        break;
      }

      case "ob_callback_found": {
        const pre = d.pre_driver ?? "none";
        const post = d.post_driver ?? "none";
        const drv = pre !== "none" ? pre : post;
        addLog(`[ObCallback] type=${d.type} driver=${drv} pre=${d.pre_op}(${pre}) post=${d.post_op}(${post}) ops=${d.operations} enabled=${d.enabled}`, "obcb");
        break;
      }

      case "ob_callback_scan_complete":
        addLog("[ObCallback] Scan complete", "obcb");
        break;

      case "ob_callback_error":
        addLog(`[ObCallback] Error scanning ${d.type}: ${d.error}`, "err");
        break;

      case "system_check": {
        const check = d.check ?? "?";
        if (d.error) {
          addLog(`[System Check] ${check}: ERROR - ${d.error}`, "err");
        } else if (check === "test_sign") {
          if (d.test_signing)
            addLog(`[Test-Sign] DETECTED - Test signing is ENABLED (CI=${d.code_integrity_enabled})`, "suspicious");
          else
            addLog(`[System Check] Test signing disabled, Code Integrity=${d.code_integrity_enabled}`, "ok");
        } else if (check === "hvci") {
          if (!d.hvci_enabled)
            addLog(`[HVCI] WARNING - HVCI is DISABLED (audit=${d.hvci_audit_mode})`, "suspicious");
          else
            addLog(`[System Check] HVCI enabled (audit=${d.hvci_audit_mode})`, "ok");
        } else if (check === "cpu_vendor") {
          if (d.hypervisor_present)
            addLog(`[CPU] ${d.cpu_vendor} - Hypervisor DETECTED: ${d.hypervisor_vendor}`, "info");
          else
            addLog(`[CPU] ${d.cpu_vendor} - No hypervisor detected`, "info");
        }
        break;
      }

      case "system_check_complete":
        addLog("[System Check] All checks complete", "ok");
        break;

      default:
        addLog(`[${event || "unknown"}] ${JSON.stringify(d)}`, "info");
    }
  }

  function handleIpcEvent(d: any) {
    if (!d) return;
    const event = d.event ?? "";
    const caller = d.callerPID ?? "?";
    const target = d.targetPID ?? "?";

    if (event === "hello") {
      addLog(`[ok] DLL injected into PID ${caller} (${d.image ?? "?"})`, "apc_ok");
      return;
    }

    const isSelf = caller === target;
    const targetProtected = protectedPids.includes(target);
    const callerProtected = protectedPids.includes(caller);

    if (event === "ReadProcessMemory" || event === "WriteProcessMemory") {
      if (!isSelf)
        addLog(`[External ${event}] PID ${caller} → PID ${target} | ${d.size ?? 0} bytes at 0x${(d.address ?? 0).toString(16).toUpperCase()}`, "handle");
      return;
    }
    if (event === "VirtualAllocEx") {
      if (!isSelf)
        addLog(`[External VirtualAllocEx] PID ${caller} -> PID ${target} | ${d.size} bytes at 0x${(d.address??0).toString(16).toUpperCase()} protect=${d.protect}`, "handle");
      return;
    }
    if (event === "VirtualProtectEx") {
      if (!isSelf)
        addLog(`[External VirtualProtectEx] PID ${caller} -> PID ${target} | ${d.size} bytes protect=${d.newProtect}`, "handle");
      return;
    }
    if (event === "CreateRemoteThread") {
      if (!isSelf)
        addLog(`[External CreateRemoteThread] PID ${caller} -> PID ${target} | start=0x${(d.startAddress??0).toString(16).toUpperCase()}`, "remote_thr");
      return;
    }
    if (event === "OpenProcess") {
      if (!isSelf)
        addLog(`[External OpenProcess] PID ${caller} -> PID ${target} | access=${d.access}`, "handle");
      return;
    }

    addLog(`[IPC] ${event} caller=${caller} target=${target}`, "info");
  }

  onMount(async () => {
    await listen("driver-event", (ev: any) => {
      try { handleDriverEvent(ev.payload); } catch (e) { console.error("driver-event error:", e); }
    });
    await listen("ipc-event", (ev: any) => {
      try { handleIpcEvent(ev.payload); } catch (e) { console.error("ipc-event error:", e); }
    });
    await listen("etw-ti-event", (ev: any) => {
      try { handleEtwTiEvent(ev.payload); } catch (e) { console.error("etw-ti-event error:", e); }
    });
    connect();
  });
</script>

<main>
  <header>
    <div class="status-row">
      <span class="label">STATUS:</span>
      <span style="color: {statusColor}; font-weight: bold">{status}</span>
      <button class="btn-small" onclick={connect}>Reconnect</button>
    </div>
    <div class="pids">
      Protected: {protectedPids.length ? protectedPids.join(", ") : "None"}
    </div>
    <div class="pids">
      Injection targets: {injectionTargets.length ? injectionTargets.join(", ") : "None"}
    </div>
  </header>

  <nav>
    <input type="text" bind:value={pidInput} placeholder="PID" class="pid-input" />
    <button class="btn" onclick={addPid}>Add</button>
    <button class="btn" onclick={removePid}>Remove</button>
    <button class="btn" onclick={clearAll}>Clear</button>
    <button class="btn accent" onclick={setPpl}>PPL</button>
    <span style="color:#585b70">|</span>
    <input type="text" bind:value={targetInput} placeholder="target.exe" class="pid-input" style="width:110px" />
    <button class="btn accent" onclick={addTarget}>Inject</button>
    <button class="btn" onclick={clearTargets}>Clear Inj</button>
    <span style="color:#585b70">|</span>
    <button class="btn" onclick={checkModules}>Modules</button>
    <button class="btn" onclick={checkIat}>IAT</button>
    <button class="btn" onclick={checkEat}>EAT</button>
    <button class="btn" onclick={checkThreads}>Threads</button>
    <button class="btn warn" onclick={scanBlacklist}>Blacklist</button>
    <div class="spacer"></div>
    <button class="btn warn" onclick={() => driverCmd("scan_drivers")}>Drivers</button>
    <button class="btn warn" onclick={() => driverCmd("scan_ob_callbacks")}>ObCB</button>
    <button class="btn purple" onclick={() => driverCmd("system_check")}>SysChk</button>
    <button class="btn" style="background:#e74c3c;color:white" onclick={startEtwTi}>ETW-TI</button>
  </nav>

  <div class="log" bind:this={logEl}>
    {#each logs as entry (entry.id)}
      <div class="log-line" style="color: {tagColors[entry.tag] ?? tagColors.default}">
        <span class="ts">{entry.ts}</span> {entry.text}
      </div>
    {/each}
  </div>
</main>

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    background: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Consolas', 'Fira Code', monospace;
    font-size: 13px;
    overflow: hidden;
    height: 100vh;
  }
  main {
    display: flex;
    flex-direction: column;
    height: 100vh;
    padding: 8px 12px;
    box-sizing: border-box;
    gap: 6px;
  }
  header {
    flex-shrink: 0;
  }
  .status-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .label { color: #888; font-weight: bold; }
  .pids { color: #888; font-size: 12px; margin-top: 2px; }
  nav {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .spacer { flex: 1; }
  .pid-input {
    width: 80px;
    background: #313244;
    border: 1px solid #45475a;
    color: #cdd6f4;
    padding: 4px 8px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 13px;
    outline: none;
  }
  .pid-input:focus { border-color: #6ab0f3; }
  .btn, .btn-small {
    background: #45475a;
    color: #cdd6f4;
    border: none;
    padding: 4px 10px;
    border-radius: 4px;
    cursor: pointer;
    font-family: inherit;
    font-size: 12px;
  }
  .btn:hover, .btn-small:hover { background: #585b70; }
  .btn-small { font-size: 11px; padding: 2px 8px; }
  .btn.accent { background: #4a90e2; color: white; }
  .btn.accent:hover { background: #5ba0f2; }
  .btn.warn { background: #e67e22; color: white; }
  .btn.warn:hover { background: #f08e32; }
  .btn.purple { background: #a78bfa; color: white; }
  .btn.purple:hover { background: #b79bff; }
  .log {
    flex: 1;
    overflow-y: auto;
    background: #11111b;
    border-radius: 6px;
    padding: 8px;
    scrollbar-width: thin;
    scrollbar-color: #45475a #11111b;
  }
  .log-line {
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.5;
  }
  .ts {
    color: #585b70;
    margin-right: 6px;
  }
</style>
