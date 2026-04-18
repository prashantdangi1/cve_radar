(() => {
  const DATA_URL = "data/cves.json";
  const KEV_URL =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

  const state = {
    items: [],
    generatedAt: null,
    filters: { window: "today", minCvss: 8, q: "" },
  };

  const els = {
    list: document.getElementById("cve-list"),
    empty: document.getElementById("empty"),
    status: document.getElementById("status-text"),
    updated: document.getElementById("last-updated"),
    statToday: document.getElementById("stat-today"),
    statCritical: document.getElementById("stat-critical"),
    statKev: document.getElementById("stat-kev"),
    statVendors: document.getElementById("stat-vendors"),
    window: document.getElementById("window"),
    minCvss: document.getElementById("min-cvss"),
    q: document.getElementById("q"),
    refresh: document.getElementById("refresh"),
    tpl: document.getElementById("cve-card-tpl"),
  };

  const todayISO = () => new Date().toISOString().slice(0, 10);
  const fmtDate = (d) => (d ? new Date(d).toISOString().slice(0, 10) : "");

  const setStatus = (msg, tone = "ok") => {
    els.status.textContent = msg;
    els.status.dataset.tone = tone;
  };

  async function loadStatic() {
    try {
      const res = await fetch(DATA_URL, { cache: "no-cache" });
      if (!res.ok) throw new Error(`status ${res.status}`);
      const data = await res.json();
      state.items = data.items || [];
      state.generatedAt = data.generatedAt || null;
      return true;
    } catch (e) {
      console.warn("Static data unavailable:", e.message);
      return false;
    }
  }

  async function loadLiveKEV() {
    setStatus("Fetching CISA KEV live\u2026");
    const res = await fetch(KEV_URL, { cache: "no-cache" });
    if (!res.ok) throw new Error(`KEV ${res.status}`);
    const data = await res.json();
    const today = todayISO();
    const items = (data.vulnerabilities || []).map((v) => ({
      cveID: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      description: v.shortDescription,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: (v.knownRansomwareCampaignUse || "").toLowerCase() === "known",
      requiredAction: v.requiredAction,
      cvss: null,
      kev: true,
      isToday: v.dateAdded === today,
    }));
    state.items = items;
    state.generatedAt = data.dateReleased || new Date().toISOString();
  }

  function withinWindow(item, win) {
    if (!item.dateAdded) return false;
    const now = Date.now();
    const added = new Date(item.dateAdded).getTime();
    if (Number.isNaN(added)) return false;
    if (win === "today") return fmtDate(added) === todayISO();
    const days = win === "7d" ? 7 : 30;
    return now - added <= days * 86400000;
  }

  function passesFilters(item) {
    if (!item.kev) return false;
    if (!withinWindow(item, state.filters.window)) return false;
    const cvss = typeof item.cvss === "number" ? item.cvss : null;
    if (cvss !== null && cvss < state.filters.minCvss) return false;
    const q = state.filters.q.trim().toLowerCase();
    if (q) {
      const hay = `${item.cveID} ${item.vendor} ${item.product} ${item.name} ${item.description}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function severityFor(cvss) {
    if (cvss == null) return { label: "KEV \u00b7 in the wild", cls: "high" };
    if (cvss >= 9) return { label: `${cvss.toFixed(1)} \u00b7 critical`, cls: "critical" };
    if (cvss >= 7) return { label: `${cvss.toFixed(1)} \u00b7 high`, cls: "high" };
    return { label: cvss.toFixed(1), cls: "" };
  }

  function render() {
    const visible = state.items.filter(passesFilters).sort((a, b) => {
      const ad = new Date(b.dateAdded) - new Date(a.dateAdded);
      if (ad !== 0) return ad;
      return (b.cvss ?? 0) - (a.cvss ?? 0);
    });

    els.list.innerHTML = "";
    els.empty.classList.toggle("hidden", visible.length > 0);

    for (const item of visible) {
      const node = els.tpl.content.firstElementChild.cloneNode(true);
      const sev = severityFor(item.cvss);

      const idLink = node.querySelector(".cve-id");
      idLink.textContent = item.cveID;
      idLink.href = `https://nvd.nist.gov/vuln/detail/${item.cveID}`;

      const sevEl = node.querySelector(".severity");
      sevEl.textContent = sev.label;
      sevEl.className = `severity ${sev.cls}`;

      node.querySelector(".title").textContent = item.name || `${item.vendor} ${item.product}`;
      node.querySelector(".desc").textContent = item.description || "";

      node.querySelector(".meta-vendor").textContent =
        `${item.vendor || "Unknown"} \u2014 ${item.product || ""}`.trim();
      node.querySelector(".meta-added").textContent = `KEV added ${fmtDate(item.dateAdded)}`;
      const dueEl = node.querySelector(".meta-due");
      if (item.dueDate) {
        dueEl.textContent = `Patch by ${fmtDate(item.dueDate)}`;
        dueEl.classList.remove("hidden");
      }

      const tags = node.querySelector(".tags");
      const kevTag = document.createElement("span");
      kevTag.className = "tag";
      kevTag.textContent = "Exploited in wild";
      tags.appendChild(kevTag);
      if (item.ransomware) {
        const r = document.createElement("span");
        r.className = "tag ransomware";
        r.textContent = "Ransomware use";
        tags.appendChild(r);
      }
      if (item.cvss != null) {
        const c = document.createElement("span");
        c.className = "tag";
        c.textContent = `CVSS ${item.cvss.toFixed(1)}`;
        tags.appendChild(c);
      }

      node.querySelector(".lnk-nvd").href = `https://nvd.nist.gov/vuln/detail/${item.cveID}`;
      node.querySelector(".lnk-kev").href =
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

      els.list.appendChild(node);
    }

    renderStats();
  }

  function renderStats() {
    const today = todayISO();
    const all = state.items;
    const todayCount = all.filter((i) => i.dateAdded === today).length;
    const critCount = all.filter((i) => (i.cvss ?? 0) >= 9).length;
    const kevCount = all.filter((i) => i.kev).length;
    const vendors = new Set(all.filter((i) => i.dateAdded === today).map((i) => i.vendor));
    els.statToday.textContent = todayCount;
    els.statCritical.textContent = critCount;
    els.statKev.textContent = kevCount;
    els.statVendors.textContent = vendors.size;
    els.updated.textContent = state.generatedAt
      ? new Date(state.generatedAt).toLocaleString()
      : "\u2014";
  }

  function bind() {
    els.window.addEventListener("change", () => {
      state.filters.window = els.window.value;
      render();
    });
    els.minCvss.addEventListener("input", () => {
      const v = parseFloat(els.minCvss.value);
      state.filters.minCvss = Number.isFinite(v) ? v : 0;
      render();
    });
    els.q.addEventListener("input", () => {
      state.filters.q = els.q.value;
      render();
    });
    els.refresh.addEventListener("click", () => boot(true));
  }

  async function boot(forceLive = false) {
    setStatus("Loading\u2026");
    let ok = false;
    if (!forceLive) ok = await loadStatic();
    if (!ok) {
      try {
        await loadLiveKEV();
        ok = true;
      } catch (e) {
        setStatus(`Live fetch failed: ${e.message}`, "err");
      }
    }
    if (ok) {
      setStatus(forceLive ? "Live KEV refreshed" : "Radar online");
      render();
    }
  }

  bind();
  boot();
})();
