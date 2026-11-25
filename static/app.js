(() => {
  const views = [...document.querySelectorAll(".view")];
  const navLinks = [...document.querySelectorAll("[data-view]")];
  const sectionName = document.getElementById("current-section");
  const reportDialog = document.getElementById("report-prompt");
  const reportOpenLink = document.getElementById("report-open");
  const reportPromptMessage = document.getElementById("report-prompt-message");
  const reportFrame = document.getElementById("report-frame");
  let selectedReport = null;
  let reportToOpen = null;
  let currentTheme = "light";
  const names = {
    dashboard: "Overview",
    signins: "Sign-in audit",
    risky: "Risky users",
    sentinel: "Sentinel / XDR",
    ipsearch: "IP intelligence",
    reports: "Reports",
    keys: "API key status",
  };
  let activeJobId = null;
  let logOffset = 0;
  let activeJobs = 0;
  let riskyAccounts = [];

  function showView(name) {
    views.forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.classList.toggle("active", link.dataset.view === name);
    });
    sectionName.textContent = names[name] || "Overview";
    if (name === "reports") loadReports();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  navLinks.forEach((link) => {
    link.addEventListener("click", () => showView(link.dataset.view));
  });
  document.querySelector("[data-view-link]").addEventListener("click", (event) => {
    event.preventDefault();
    showView("dashboard");
  });

  const themeToggle = document.getElementById("theme-toggle");
  const themeLabel = document.getElementById("theme-label");

  function setTheme(theme) {
    currentTheme = theme;
    document.documentElement.dataset.theme = theme;
    themeLabel.textContent = theme === "dark" ? "Light mode" : "Dark mode";
    localStorage.setItem("soc-theme", theme);
    if (reportFrame.dataset.loaded === "true") {
      reportFrame.contentWindow.postMessage({ type: "soc-theme", theme }, "*");
    }
  }

  const savedTheme = localStorage.getItem("soc-theme");
  setTheme(savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });

  const today = new Date();
  document.getElementById("today-date").textContent = new Intl.DateTimeFormat("en-GB", {
    weekday: "short", day: "2-digit", month: "short", year: "numeric",
  }).format(today);

  function formValues(form) {
    const data = {};
    for (const [key, value] of new FormData(form).entries()) {
      if (value instanceof File) continue;
      data[key] = value;
    }
    form.querySelectorAll('input[type="checkbox"]').forEach((input) => {
      data[input.name] = input.checked;
    });
    return data;
  }

  function addLog(entry) {
    const consoleElement = document.getElementById("job-console");
    const empty = consoleElement.querySelector(".console-empty");
    if (empty) empty.remove();
    const line = document.createElement("div");
    line.className = `console-line ${entry.tag || "default"}`;
    const time = document.createElement("span");
    time.className = "log-time";
    time.textContent = entry.time || "";
    const text = document.createElement("span");
    text.textContent = entry.message || "";
    line.append(time, text);
    consoleElement.append(line);
    consoleElement.scrollTop = consoleElement.scrollHeight;
  }

  function showError(message) {
    addLog({ tag: "danger", time: new Date().toLocaleTimeString("en-GB"), message: `[!] ${message}` });
    document.getElementById("job-status").textContent = "Unable to start the operation.";
    document.getElementById("activity-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll(".button.primary").forEach((button) => {
      button.disabled = disabled;
    });
  }

  async function startJob(url, options = {}) {
    if (activeJobId) {
      showError("An operation is already running. Wait for it to finish before starting another.");
      return;
    }
    try {
      setButtonsDisabled(true);
      document.getElementById("job-console").replaceChildren();
      document.getElementById("job-artifacts").classList.add("hidden");
      document.getElementById("job-progress").style.width = "0%";
      document.getElementById("progress-label").textContent = "0%";
      document.getElementById("job-status").textContent = "Starting operation...";
      logOffset = 0;
      const request = await fetch(url, options);
      const payload = await request.json();
      if (!request.ok) throw new Error(payload.error || "Unable to start the operation.");
      activeJobId = payload.job_id;
      activeJobs += 1;
      document.getElementById("active-jobs").textContent = String(activeJobs);
      document.getElementById("activity-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
      pollJob(activeJobId);
    } catch (error) {
      setButtonsDisabled(false);
      showError(error.message);
    }
  }

  async function pollJob(jobId) {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}?since=${logOffset}`);
      const job = await response.json();
      if (!response.ok) throw new Error(job.error || "Unable to retrieve operation progress.");
      job.logs.forEach(addLog);
      logOffset = job.log_count;
      const percent = Math.round((job.progress || 0) * 100);
      document.getElementById("job-progress").style.width = `${percent}%`;
      document.getElementById("progress-label").textContent = `${percent}%`;
      document.getElementById("job-status").textContent = job.status;
      updateResult(job);
      if (job.artifacts && job.artifacts.length) renderArtifacts(job.artifacts);
      if (job.state === "running") {
        window.setTimeout(() => pollJob(jobId), 900);
      } else {
        promptToOpenReport(job);
        activeJobId = null;
        activeJobs = Math.max(0, activeJobs - 1);
        document.getElementById("active-jobs").textContent = String(activeJobs);
        document.getElementById("risky-audit-button").disabled = riskyAccounts.length === 0;
        setButtonsDisabled(false);
        document.getElementById("last-result").textContent = job.state === "completed" ? "Complete" : "Error";
        document.getElementById("last-result-time").textContent = new Date().toLocaleTimeString("en-GB");
        if (job.state === "completed") {
          document.getElementById("job-progress").style.width = "100%";
          document.getElementById("progress-label").textContent = "100%";
        }
      }
    } catch (error) {
      activeJobId = null;
      activeJobs = Math.max(0, activeJobs - 1);
      document.getElementById("active-jobs").textContent = String(activeJobs);
      setButtonsDisabled(false);
      showError(error.message);
    }
  }

  function updateResult(job) {
    if (!job.result) return;
    if (Array.isArray(job.result.accounts)) {
      riskyAccounts = job.result.accounts;
      const count = riskyAccounts.length;
      document.getElementById("risky-count").textContent = `${count} account${count === 1 ? "" : "s"} available for audit.`;
      const list = document.getElementById("risky-account-list");
      list.replaceChildren();
      riskyAccounts.forEach((account) => {
        const chip = document.createElement("span");
        chip.className = "account-chip";
        chip.textContent = account;
        list.append(chip);
      });
      list.classList.toggle("hidden", count === 0);
      document.getElementById("risky-audit-button").disabled = count === 0 || Boolean(activeJobId);
    }
    if (Array.isArray(job.result.workspaces)) {
      const workspaces = job.result.workspaces;
      const input = document.getElementById("sentinel-workspace");
      workspaces.forEach((workspace) => {
        if (workspace.guid === input.value) return;
        const option = document.createElement("option");
        option.value = workspace.label;
        option.label = `${workspace.name} · ${workspace.subscription}`;
        let list = document.getElementById("workspace-options");
        if (!list) {
          list = document.createElement("datalist");
          list.id = "workspace-options";
          input.setAttribute("list", list.id);
          document.body.append(list);
        }
        list.append(option);
      });
      if (workspaces.length) {
        document.getElementById("job-status").textContent += " Choose a suggested workspace in the field.";
      }
    }
    if (Array.isArray(job.result.keys)) renderKeys(job.result);
  }

  function renderArtifacts(artifacts) {
    const container = document.getElementById("artifact-links");
    container.replaceChildren();
    artifacts.forEach((artifact) => {
      const link = document.createElement("a");
      link.className = "artifact-link";
      link.href = artifact.url;
      link.textContent = `↓ ${artifact.name}`;
      link.setAttribute("download", artifact.name);
      container.append(link);
    });
    document.getElementById("job-artifacts").classList.remove("hidden");
  }

  async function loadReports() {
    const list = document.getElementById("report-list");
    const count = document.getElementById("report-count");
    list.replaceChildren();
    count.textContent = "Loading reports...";
    try {
      const response = await fetch("/api/reports");
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to load reports.");
      const reports = payload.reports || [];
      count.textContent = `${reports.length} saved report${reports.length === 1 ? "" : "s"}`;
      if (!reports.length) {
        const empty = document.createElement("div");
        empty.className = "report-list-empty";
        empty.textContent = "No HTML reports have been generated yet.";
        list.append(empty);
        clearReportPreview();
        return;
      }

      const activeReport = reports.find((report) =>
        selectedReport && report.folder === selectedReport.folder && report.name === selectedReport.name
      ) || reports[0];
      reports.forEach((report) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "report-item";
        button.dataset.folder = report.folder;
        button.dataset.name = report.name;
        const title = document.createElement("strong");
        title.textContent = report.name;
        const details = document.createElement("small");
        details.textContent = `${report.folder} · ${new Date(report.modified).toLocaleString("en-GB")}`;
        button.append(title, details);
        button.addEventListener("click", () => displayReport(report));
        list.append(button);
      });
      displayReport(activeReport);
    } catch (error) {
      count.textContent = "Unable to load reports.";
      const message = document.createElement("div");
      message.className = "report-list-empty";
      message.textContent = error.message;
      list.append(message);
    }
  }

  function displayReport(report) {
    selectedReport = report;
    document.getElementById("report-preview-title").textContent = report.name;
    document.getElementById("report-preview-meta").textContent =
      `${report.folder} · ${report.modified ? new Date(report.modified).toLocaleString("en-GB") : "Just generated"}`;
    const download = document.getElementById("report-download");
    download.href = report.url;
    download.classList.remove("hidden");
    document.getElementById("report-preview-empty").classList.add("hidden");
    reportFrame.classList.remove("hidden");
    reportFrame.dataset.loaded = "false";
    reportFrame.src = `${report.url}?view=inline`;
    document.querySelectorAll(".report-item").forEach((item) => {
      item.classList.toggle(
        "selected",
        item.dataset.folder === report.folder && item.dataset.name === report.name
      );
    });
  }

  function clearReportPreview() {
    selectedReport = null;
    document.getElementById("report-preview-title").textContent = "Report preview";
    document.getElementById("report-preview-meta").textContent = "Select a report to preview it here.";
    document.getElementById("report-download").classList.add("hidden");
    reportFrame.classList.add("hidden");
    reportFrame.dataset.loaded = "false";
    reportFrame.src = "about:blank";
    document.getElementById("report-preview-empty").classList.remove("hidden");
  }

  reportFrame.addEventListener("load", () => {
    if (reportFrame.src === "about:blank") return;
    reportFrame.dataset.loaded = "true";
    reportFrame.contentWindow.postMessage({ type: "soc-theme", theme: currentTheme }, "*");
  });

  function promptToOpenReport(job) {
    if (job.state !== "completed" || !reportDialog.showModal) return;
    const report = job.artifacts.find((artifact) => artifact.name.toLowerCase().endsWith(".html"));
    if (!report) return;
    reportToOpen = report;
    reportPromptMessage.textContent = `The HTML report "${report.name}" was generated. Would you like to open it?`;
    reportDialog.showModal();
  }

  function renderKeys(result) {
    document.getElementById("key-total").textContent = `${result.remaining} / ${result.limit}`;
    const usage = result.limit ? ((result.limit - result.remaining) / result.limit) * 100 : 0;
    document.getElementById("key-usage").style.width = `${Math.max(0, Math.min(100, usage))}%`;
    document.getElementById("key-count").textContent = `${result.keys.length} keys checked`;
    const list = document.getElementById("key-results");
    list.replaceChildren();
    result.keys.forEach((key) => {
      const row = document.createElement("div");
      row.className = "key-row";
      const label = document.createElement("span");
      label.className = "key-label";
      label.textContent = `Key #${key.index} · ${key.key}`;
      const status = document.createElement("span");
      status.className = `key-state ${key.status === "Active" ? "" : "bad"}`;
      status.textContent = key.status;
      const remaining = document.createElement("span");
      remaining.className = "key-remaining";
      remaining.textContent = `Remaining: ${key.remaining} / ${key.limit} · Used: ${key.used_pct} · Reset: ${key.reset}`;
      row.append(label, status, remaining);
      list.append(row);
    });
  }

  function postJson(url, data) {
    return startJob(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
  }

  document.getElementById("signins-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formValues(form);
    if (data.mode === "bulk") {
      const file = document.getElementById("signin-file").files[0];
      if (file) data.targets = await file.text();
      delete data.target;
    } else {
      delete data.targets;
    }
    await postJson("/api/signins", data);
  });

  document.getElementById("signin-mode").addEventListener("change", (event) => {
    const bulk = event.target.value === "bulk";
    document.getElementById("signin-single-field").classList.toggle("hidden", bulk);
    document.getElementById("signin-bulk-fields").classList.toggle("hidden", !bulk);
  });

  document.getElementById("risky-scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await postJson("/api/risky/scan", formValues(event.currentTarget));
  });
  document.getElementById("risky-audit-button").addEventListener("click", async () => {
    if (!riskyAccounts.length) return;
    await postJson("/api/risky/audit", {
      days: document.getElementById("risky-audit-days").value,
      use_abuse: document.getElementById("risky-use-abuse").checked,
    });
  });

  document.getElementById("sentinel-engine").addEventListener("change", (event) => {
    const isSentinel = event.target.value === "Sentinel Workspace";
    document.getElementById("workspace-field").classList.toggle("hidden", !isSentinel);
    document.getElementById("discover-workspaces").disabled = !isSentinel;
  });
  document.getElementById("discover-workspaces").addEventListener("click", () => {
    startJob("/api/sentinel/discover", { method: "POST" });
  });
  document.getElementById("sentinel-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await postJson("/api/sentinel/query", formValues(event.currentTarget));
  });

  function updateIpMode() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    document.querySelectorAll(".mode-card").forEach((card) => {
      card.classList.toggle("selected", card.querySelector("input").checked);
    });
    document.getElementById("ip-single-field").classList.toggle("hidden", mode !== "single");
    document.getElementById("ip-bulk-field").classList.toggle("hidden", mode !== "bulk");
    document.getElementById("ip-sentinel-fields").classList.toggle("hidden", mode !== "sentinel");
  }
  document.querySelectorAll('#ipsearch-form input[name="mode"]').forEach((input) => input.addEventListener("change", updateIpMode));
  document.getElementById("ipsearch-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const mode = form.querySelector('input[name="mode"]:checked').value;
    const body = new FormData(form);
    if (mode !== "sentinel") body.delete("workspace");
    body.set("use_intigriti", String(form.querySelector('input[name="use_intigriti"]').checked));
    await startJob("/api/ipsearch", { method: "POST", body });
  });

  document.getElementById("check-keys").addEventListener("click", () => {
    startJob("/api/keys/check", { method: "POST" });
  });
  document.getElementById("clear-log").addEventListener("click", () => {
    document.getElementById("job-console").replaceChildren();
    document.getElementById("job-console").innerHTML =
      '<div class="console-empty"><span>⌁</span><strong>Console cleared</strong><small>The next operation will appear here.</small></div>';
  });
  document.getElementById("refresh-reports").addEventListener("click", loadReports);
  document.getElementById("report-stay").addEventListener("click", () => {
    reportToOpen = null;
    reportDialog.close();
  });
  reportOpenLink.addEventListener("click", () => {
    reportDialog.close();
    if (reportToOpen) {
      const report = reportToOpen;
      reportToOpen = null;
      showView("reports");
      displayReport(report);
    }
  });

  const onlySidInput = document.querySelector('#signins-form input[name="only_sid"]');
  onlySidInput.addEventListener("change", () => {
    const onlySid = onlySidInput.checked;
    document.querySelector('#signins-form input[name="days"]').disabled = onlySid;
    document.querySelector('#signins-form input[name="use_abuse"]').disabled = onlySid;
    document.querySelector('#signins-form button[type="submit"]').innerHTML =
      onlySid ? "Translate SID" : "<span>▶</span> Run audit";
  });
})();
