(() => {
  const views = [...document.querySelectorAll(".view")];
  const navLinks = [...document.querySelectorAll("[data-view]")];
  const sectionName = document.getElementById("current-section");
  const names = {
    dashboard: "Resumen",
    signins: "Auditoría de accesos",
    risky: "Usuarios de riesgo",
    sentinel: "Sentinel / XDR",
    ipsearch: "Inteligencia de IP",
    keys: "Estado de API keys",
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
    sectionName.textContent = names[name] || "Resumen";
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
    document.documentElement.dataset.theme = theme;
    themeLabel.textContent = theme === "dark" ? "Modo claro" : "Modo oscuro";
    localStorage.setItem("soc-theme", theme);
  }

  const savedTheme = localStorage.getItem("soc-theme");
  setTheme(savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });

  const today = new Date();
  document.getElementById("today-date").textContent = new Intl.DateTimeFormat("es-ES", {
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
    addLog({ tag: "danger", time: new Date().toLocaleTimeString("es-ES"), message: `[!] ${message}` });
    document.getElementById("job-status").textContent = "No se pudo iniciar la operación.";
    document.getElementById("activity-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll(".button.primary").forEach((button) => {
      button.disabled = disabled;
    });
  }

  async function startJob(url, options = {}) {
    if (activeJobId) {
      showError("Ya hay una operación activa. Espera a que termine antes de iniciar otra.");
      return;
    }
    try {
      setButtonsDisabled(true);
      document.getElementById("job-console").replaceChildren();
      document.getElementById("job-artifacts").classList.add("hidden");
      document.getElementById("job-progress").style.width = "0%";
      document.getElementById("progress-label").textContent = "0%";
      document.getElementById("job-status").textContent = "Iniciando operación...";
      logOffset = 0;
      const request = await fetch(url, options);
      const payload = await request.json();
      if (!request.ok) throw new Error(payload.error || "No se pudo iniciar la operación.");
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
      if (!response.ok) throw new Error(job.error || "No se pudo consultar el progreso.");
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
        activeJobId = null;
        activeJobs = Math.max(0, activeJobs - 1);
        document.getElementById("active-jobs").textContent = String(activeJobs);
        document.getElementById("risky-audit-button").disabled = riskyAccounts.length === 0;
        setButtonsDisabled(false);
        document.getElementById("last-result").textContent = job.state === "completed" ? "Completo" : "Error";
        document.getElementById("last-result-time").textContent = new Date().toLocaleTimeString("es-ES");
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
      document.getElementById("risky-count").textContent = `${count} cuenta${count === 1 ? "" : "s"} disponibles para auditoría.`;
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
        document.getElementById("job-status").textContent += " Selecciona un workspace sugerido en el campo.";
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

  function renderKeys(result) {
    document.getElementById("key-total").textContent = `${result.remaining} / ${result.limit}`;
    const usage = result.limit ? ((result.limit - result.remaining) / result.limit) * 100 : 0;
    document.getElementById("key-usage").style.width = `${Math.max(0, Math.min(100, usage))}%`;
    document.getElementById("key-count").textContent = `${result.keys.length} claves comprobadas`;
    const list = document.getElementById("key-results");
    list.replaceChildren();
    result.keys.forEach((key) => {
      const row = document.createElement("div");
      row.className = "key-row";
      const label = document.createElement("span");
      label.className = "key-label";
      label.textContent = `Clave #${key.index} · ${key.key}`;
      const status = document.createElement("span");
      status.className = `key-state ${key.status === "Active" ? "" : "bad"}`;
      status.textContent = key.status;
      const remaining = document.createElement("span");
      remaining.className = "key-remaining";
      remaining.textContent = `Disponibles: ${key.remaining} / ${key.limit} · Uso: ${key.used_pct} · Reinicio: ${key.reset}`;
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
      '<div class="console-empty"><span>⌁</span><strong>Consola limpia</strong><small>La próxima operación aparecerá aquí.</small></div>';
  });

  const onlySidInput = document.querySelector('#signins-form input[name="only_sid"]');
  onlySidInput.addEventListener("change", () => {
    const onlySid = onlySidInput.checked;
    document.querySelector('#signins-form input[name="days"]').disabled = onlySid;
    document.querySelector('#signins-form input[name="use_abuse"]').disabled = onlySid;
    document.querySelector('#signins-form button[type="submit"]').innerHTML =
      onlySid ? "Traducir SID" : "<span>▶</span> Iniciar auditoría";
  });
})();
