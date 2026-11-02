/* CyberSentinel dashboard: SSE live progress + findings triage table. */
(() => {
  "use strict";

  const STAGES = [
    { key: "discovery", label: "Nmap service discovery" },
    { key: "zap", label: "ZAP spider + active scan" },
    { key: "tls", label: "SSLyze TLS audit" },
    { key: "harvest", label: "Harvest & triage findings" },
  ];
  const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
  const EVENT_NAMES = [
    "scan.queued", "scan.started", "scan.finished", "scan.cancelling",
    "stage", "progress", "urls", "services", "plan", "finding",
    "summary", "log", "error",
  ];

  const el = (id) => document.getElementById(id);
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  };

  const state = {
    scanId: null,
    source: null,
    status: "idle",
    findings: [],
    stages: {},
    filter: { severities: new Set(), scanType: "all", query: "" },
    sort: "severity",
    timer: null,
    startedAt: null,
    seenUrls: 0,
  };

  // ----------------------------------------------------------------- stages
  function renderStages() {
    const list = el("stages");
    list.replaceChildren();
    for (const stage of STAGES) {
      const status = state.stages[stage.key] || { state: "pending", message: "" };
      const li = node("li", `is-${status.state}`);
      li.append(node("span", "dot"), node("span", "stage-label", stage.label), node("span", "stage-note", status.message));
      li.title = status.message || `${stage.key}: ${status.state}`;
      list.append(li);
    }
  }

  function setStage(key, stageState, message) {
    if (!key) return;
    const previous = state.stages[key] || { state: "pending", message: "" };
    // The pipeline reports "started"; the stepper renders it as "running".
    const next = stageState === "started" ? "running" : stageState;
    // Never demote a completed stage when a later service re-enters it.
    const rank = { pending: 0, skipped: 0, running: 1, failed: 2, completed: 3 };
    if (rank[next] >= rank[previous.state] || next === "running") {
      state.stages[key] = { state: next, message: message || previous.message };
    }
    if (next === "completed" && key === "zap") setBars(100, 100);
    renderStages();
  }

  // ------------------------------------------------------------- progress
  function setBars(spider, active) {
    el("bar-spider").style.width = `${clamp(spider)}%`;
    el("bar-active").style.width = `${clamp(active)}%`;
    el("pct-spider").textContent = `${clamp(spider)}%`;
    el("pct-active").textContent = `${clamp(active)}%`;
  }

  const clamp = (value) => Math.max(0, Math.min(100, Number(value) || 0));

  function startTimer() {
    state.startedAt = Date.now();
    clearInterval(state.timer);
    state.timer = setInterval(() => {
      el("meta-elapsed").textContent = formatElapsed(Date.now() - state.startedAt);
    }, 1000);
  }

  const stopTimer = () => clearInterval(state.timer);

  function formatElapsed(ms) {
    const total = Math.max(0, Math.floor(ms / 1000));
    const mm = String(Math.floor(total / 60)).padStart(2, "0");
    const ss = String(total % 60).padStart(2, "0");
    return `${mm}:${ss}`;
  }

  function setStatus(status) {
    state.status = status;
    const badge = el("scan-status");
    badge.className = `status status-${status}`;
    badge.textContent = status.replace(/_/g, " ");
    el("start-btn").disabled = status === "running" || status === "queued";
    el("stop-btn").disabled = status !== "running" && status !== "queued";
  }

  function appendLog(message, kind) {
    const log = el("log");
    const line = node("div", kind ? `is-${kind}` : undefined, message);
    log.append(line);
    while (log.childElementCount > 400) log.firstElementChild.remove();
    log.scrollTop = log.scrollHeight;
  }

  // -------------------------------------------------------------- findings
  function addFinding(finding) {
    state.findings.push(finding);
    scheduleFindingsRender();
  }

  let renderQueued = false;
  function scheduleFindingsRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      renderFindings();
    });
  }

  function visibleFindings() {
    const { severities, scanType, query } = state.filter;
    const needle = query.trim().toLowerCase();
    const matches = state.findings.filter((finding) => {
      if (severities.size && !severities.has(finding.severity)) return false;
      if (scanType !== "all" && finding.scan_type !== scanType) return false;
      if (!needle) return true;
      return [finding.title, finding.endpoint_url, finding.parameter, finding.evidence]
        .some((value) => String(value || "").toLowerCase().includes(needle));
    });
    matches.sort(compareFindings);
    return matches;
  }

  function compareFindings(a, b) {
    if (state.sort === "title") return String(a.title).localeCompare(String(b.title));
    if (state.sort === "url") return String(a.endpoint_url).localeCompare(String(b.endpoint_url));
    const delta = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    return delta !== 0 ? delta : String(a.title).localeCompare(String(b.title));
  }

  function renderFindings() {
    renderSeverityChips();
    const container = el("findings");
    const visible = visibleFindings();
    container.replaceChildren(...visible.map(renderFindingCard));
    el("findings-empty").hidden = state.findings.length > 0;
    if (state.findings.length > 0 && visible.length === 0) {
      container.append(node("p", "empty", "No findings match the current filters."));
    }
  }

  function renderSeverityChips() {
    const counts = new Map(SEVERITY_ORDER.map((severity) => [severity, 0]));
    for (const finding of state.findings) {
      counts.set(finding.severity, (counts.get(finding.severity) || 0) + 1);
    }
    const wrap = el("severity-chips");
    wrap.replaceChildren();
    for (const severity of SEVERITY_ORDER) {
      const count = counts.get(severity) || 0;
      const chip = node("button", `sev-chip sev-${severity.toLowerCase()} ${state.filter.severities.has(severity) ? "is-active" : ""}`);
      chip.type = "button";
      chip.append(node("span", null, `${severity} ${count}`));
      chip.disabled = count === 0;
      chip.addEventListener("click", () => {
        if (state.filter.severities.has(severity)) state.filter.severities.delete(severity);
        else state.filter.severities.add(severity);
        renderFindings();
      });
      wrap.append(chip);
    }
  }

  function renderFindingCard(finding) {
    const card = node("article", "finding");
    const head = node("div", "finding-head");
    head.append(node("span", `badge sev-${finding.severity.toLowerCase()}`, finding.severity));

    const title = node("span", "finding-title");
    title.append(node("span", null, finding.title));
    title.append(node("span", "kind", finding.scan_type === "active" ? "active exploit" : "passive warning"));
    head.append(title);

    head.append(node("span", "finding-param", finding.parameter ? `param: ${finding.parameter}` : "no parameter"));
    head.append(node("span", "caret", "details"));

    const body = node("div", "finding-body-details");
    body.append(node("p", "description", finding.description || "No description supplied by the scanner."));

    const grid = node("div", "grid-detail");
    grid.append(detail("Severity", finding.severity));
    grid.append(detail("Confidence", finding.confidence || "Not stated"));
    grid.append(detail("Vulnerable parameter", finding.parameter || "Not parameter-bound"));
    grid.append(detail("CWE", finding.cwe ? `CWE-${finding.cwe}` : "Not mapped"));
    grid.append(detail("Source", finding.source || "Unknown scanner"));
    grid.append(urlDetail("Affected URL", finding.endpoint_url));
    if (finding.reference) grid.append(urlDetail("Reference", finding.reference));

    if (finding.payload) grid.append(preDetail("Attack payload", finding.payload, "payload"));
    grid.append(preDetail("Evidence", finding.evidence || "No evidence captured", "evidence"));
    grid.append(preDetail("Recommended fix", finding.mitigation || "No remediation guidance supplied.", "fix"));
    body.append(grid);

    head.addEventListener("click", () => card.classList.toggle("is-open"));
    card.append(head, body);
    if (finding.severity === "Critical" || finding.severity === "High") card.classList.add("is-open");
    return card;
  }

  function detail(label, value) {
    const wrapper = node("div", "kv");
    wrapper.append(node("dt", null, label), node("dd", null, value));
    return wrapper;
  }

  function preDetail(label, value, className) {
    const wrapper = node("div", "kv");
    wrapper.append(node("dt", null, label));
    const pre = node("dd");
    pre.append(node("pre", className, value));
    wrapper.append(pre);
    return wrapper;
  }

  function urlDetail(label, value) {
    const wrapper = node("div", "kv");
    wrapper.append(node("dt", null, label));
    const dd = node("dd");
    if (value && /^https?:\/\//i.test(value)) {
      const link = node("a", "mono", value);
      link.href = value;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      dd.append(link);
    } else {
      dd.append(node("span", "mono", value || "Unknown endpoint"));
    }
    wrapper.append(dd);
    return wrapper;
  }

  // ----------------------------------------------------------------- events
  function resetForScan(scanId) {
    state.scanId = scanId;
    state.findings = [];
    state.stages = {};
    state.seenUrls = 0;
    el("log").replaceChildren();
    el("urls").replaceChildren();
    el("services").replaceChildren();
    el("urls-count").textContent = "0";
    el("services-count").textContent = "0";
    setBars(0, 0);
    renderStages();
    renderFindings();
  }

  function handleEvent(event) {
    const data = event.data || {};
    switch (event.type) {
      case "scan.queued":
        setStatus("queued");
        break;
      case "scan.started":
        setStatus("running");
        el("meta-scan").textContent = state.scanId || "—";
        el("meta-target").textContent = data.target_url || "—";
        startTimer();
        appendLog(`Scan ${state.scanId} started against ${data.target_url || ""}`, "stage");
        break;
      case "stage":
        setStage(data.stage, data.status, data.message);
        break;
      case "progress":
        setBars(data.spider_percent, data.active_percent);
        el("meta-elapsed").textContent = formatElapsed((data.elapsed || 0) * 1000);
        if (data.job && data.job !== "processing") setStage("zap", "running", `${data.job} ${data.active_percent || 0}%`);
        break;
      case "urls":
        renderUrls(data.urls || []);
        break;
      case "services":
        renderServices(data.services || []);
        break;
      case "plan":
        appendLog(`Generated plan ${data.plan_path} (scope: ${data.policy})`);
        break;
      case "finding":
        addFinding(data);
        break;
      case "log":
        if (data.message) appendLog(data.message);
        break;
      case "error":
        appendLog(`ERROR: ${data.message}`, "error");
        break;
      case "summary":
        appendLog(
          `Harvested ${data.findings.length} finding(s) — status ${data.status}`,
          "stage"
        );
        break;
      case "scan.cancelling":
        appendLog("Cancellation requested.", "stage");
        break;
      case "scan.finished":
        setStatus(data.status || "completed");
        stopTimer();
        if (data.error) appendLog(`Scan ended: ${data.error}`, "error");
        for (const stage of STAGES) {
          if (!state.stages[stage.key]) setStage(stage.key, data.status === "failed" ? "failed" : "skipped");
        }
        loadHistory();
        break;
      default:
        break;
    }
  }

  function renderUrls(urls) {
    const list = el("urls");
    list.replaceChildren();
    for (const url of urls) {
      const li = node("li");
      li.append(node("span", null, url));
      list.append(li);
    }
    state.seenUrls = urls.length;
    el("urls-count").textContent = String(urls.length);
  }

  function renderServices(services) {
    const list = el("services");
    list.replaceChildren();
    for (const service of services) {
      const li = node("li");
      li.append(
        node("span", "mono", `${service.host}:${service.port}/${service.protocol}`),
        node("span", null, `${service.service_name}${service.product ? ` ${service.product}` : ""}`)
      );
      list.append(li);
    }
    el("services-count").textContent = String(services.length);
  }

  // ------------------------------------------------------------------ SSE
  function connect(scanId) {
    if (state.source) state.source.close();
    resetForScan(scanId);
    const source = new EventSource(`/api/scans/${scanId}/events`);
    state.source = source;
    for (const name of EVENT_NAMES) {
      source.addEventListener(name, (raw) => handleEvent(JSON.parse(raw.data)));
    }
    source.addEventListener("scan.finished", () => source.close());
    source.onerror = () => {
      appendLog("Live stream interrupted; reconnecting…");
    };
  }

  // --------------------------------------------------------------- controls
  async function submitScan(event) {
    event.preventDefault();
    hideError();
    const payload = {
      target_url: el("target-url").value.trim(),
      cookie: el("cookie").value.trim() || null,
      policy: el("policy").value,
      zap_url: el("zap-url").value.trim() || undefined,
      zap_timeout: Number(el("zap-timeout").value),
      authorized: el("authorized").checked,
    };
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
      connect(body.scan_id);
      loadHistory();
    } catch (error) {
      showError(error.message);
    }
  }

  function showError(message) {
    const element = el("form-error");
    element.textContent = message;
    element.hidden = false;
  }

  function hideError() {
    el("form-error").hidden = true;
  }

  async function stopScan() {
    if (!state.scanId) return;
    hideError();
    try {
      const response = await fetch(`/api/scans/${state.scanId}/stop`, { method: "POST" });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `Stop failed (${response.status})`);
      }
    } catch (error) {
      showError(error.message);
    }
  }

  async function loadHealth() {
    const zapUrl = el("zap-url").value.trim();
    try {
      const response = await fetch(`/api/health?zap_url=${encodeURIComponent(zapUrl)}`);
      const health = await response.json();
      const zap = el("health").querySelector('[data-key="zap"]');
      zap.textContent = health.zap.reachable ? `ZAP ${health.zap.version} online` : `ZAP offline at ${health.zap.base_url}`;
      zap.className = `chip ${health.zap.reachable ? "chip-ok" : "chip-bad"}`;
      const nmap = el("health").querySelector('[data-key="nmap"]');
      nmap.textContent = health.nmap.available ? "Nmap available" : "Nmap missing";
      nmap.className = `chip ${health.nmap.available ? "chip-ok" : "chip-bad"}`;
      if (health.active_scan) connect(health.active_scan);
    } catch (error) {
      const zap = el("health").querySelector('[data-key="zap"]');
      zap.textContent = "Dashboard API unreachable";
      zap.className = "chip chip-bad";
    }
  }

  async function loadHistory() {
    try {
      const response = await fetch("/api/scans");
      const jobs = await response.json();
      const list = el("history");
      list.replaceChildren();
      for (const job of jobs) {
        const li = node("li", job.id === state.scanId ? "is-selected" : "");
        li.append(
          node("span", "url", job.request.target_url),
          node("span", null, `${job.finding_count} findings`),
          node(
            "span",
            "sub",
            `${job.status.replace(/_/g, " ")} · ${job.request.policy} · ${new Date(job.started_at * 1000).toLocaleTimeString()}`
          )
        );
        li.addEventListener("click", () => loadScan(job.id));
        list.append(li);
      }
    } catch (error) {
      /* history is best-effort */
    }
  }

  async function loadScan(scanId) {
    hideError();
    try {
      const response = await fetch(`/api/scans/${scanId}`);
      if (!response.ok) throw new Error(`Could not load scan ${scanId}`);
      const job = await response.json();
      if (job.status === "running" || job.status === "queued") {
        connect(scanId);
        return;
      }
      resetForScan(scanId);
      setStatus(job.status);
      el("meta-scan").textContent = job.id;
      el("meta-target").textContent = job.request.target_url;
      for (const event of job.events) handleEvent(event);
      el("meta-elapsed").textContent = formatElapsed(((job.finished_at || Date.now() / 1000) - job.started_at) * 1000);
      stopTimer();
      if (state.source) { state.source.close(); state.source = null; }
    } catch (error) {
      showError(error.message);
    }
  }

  // -------------------------------------------------------------- bootstrap
  function bindControls() {
    el("scan-form").addEventListener("submit", submitScan);
    el("stop-btn").addEventListener("click", stopScan);
    el("zap-url").addEventListener("change", loadHealth);
    el("finding-search").addEventListener("input", (event) => {
      state.filter.query = event.target.value;
      renderFindings();
    });
    el("finding-sort").addEventListener("change", (event) => {
      state.sort = event.target.value;
      renderFindings();
    });
    for (const tab of el("scan-type-tabs").querySelectorAll(".tab")) {
      tab.addEventListener("click", () => {
        state.filter.scanType = tab.dataset.scanType;
        for (const other of el("scan-type-tabs").querySelectorAll(".tab")) {
          other.classList.toggle("is-active", other === tab);
        }
        renderFindings();
      });
    }
  }

  renderStages();
  renderFindings();
  bindControls();
  setStatus("idle");
  loadHealth();
  loadHistory();
})();
