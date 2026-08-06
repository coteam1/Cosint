"use strict";

const $ = (id) => document.getElementById(id);
const CATS = {
  identity: "الهوية", accounts: "الحسابات", breaches: "التسريبات",
  phone: "الهاتف", google: "Google", infra: "البنية التحتية", misc: "أخرى",
};
const CAT_ORDER = ["breaches", "identity", "google", "accounts", "phone", "infra", "misc"];
const SEV = { high: 0, notable: 1, info: 2 };
const PIVOT_TYPES = ["username", "phone", "domain"];

let poller = null, cy = null, catalog = [], currentJob = null, railType = null;

/* ---------- boot ---------- */
init();

async function init() {
  wireForm();
  wireTabs();
  await loadCatalog();
  await loadHistory();
  const hash = location.hash.slice(1);
  if (hash) attach(hash);
}

async function loadCatalog() {
  try {
    const r = await fetch("/api/modules");
    const d = await r.json();
    catalog = d.modules || [];
    $("pips").innerHTML = Object.entries(d.tools || {})
      .map(([k, on]) => `<span class="pip ${on ? "on" : ""}" title="${on ? "مثبّت" : "غير مثبّت"}">${k}</span>`)
      .join("");
  } catch { /* offline is survivable */ }
}

async function loadHistory() {
  try {
    const r = await fetch("/api/scans?limit=8");
    const d = await r.json();
    $("history").innerHTML = (d.jobs || []).map(j =>
      `<a href="#${j.id}" data-job="${j.id}">${esc(j.target)}
        <span class="mono">${j.status} · ${fmtDate(j.created_at)}</span></a>`
    ).join("") || '<span style="color:var(--dim);font-size:12px">لا شيء بعد</span>';
    $("history").querySelectorAll("a").forEach(a =>
      a.addEventListener("click", (e) => { e.preventDefault(); attach(a.dataset.job); }));
  } catch { /* ignore */ }
}

/* ---------- form ---------- */
function wireForm() {
  const target = $("target"), consent = $("consent"), run = $("run");
  const check = () => { run.disabled = !(target.value.trim().length > 2 && consent.checked); };
  target.addEventListener("input", check);
  consent.addEventListener("change", check);
  target.addEventListener("keydown", (e) => { if (e.key === "Enter" && !run.disabled) start(); });
  run.addEventListener("click", start);
  $("again").addEventListener("click", () => {
    stopPolling(); $("result").hidden = true; $("idle").hidden = false;
    $("rail").hidden = true; location.hash = ""; target.focus();
  });
}

async function start() {
  stopPolling();
  const body = {
    target: $("target").value.trim(),
    target_type: $("ttype").value,
    pivot: $("pivot").checked,
  };
  $("run").disabled = true;
  $("run").textContent = "جارٍ التشغيل…";
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(await r.text());
    const d = await r.json();
    location.hash = d.job_id;
    attach(d.job_id);
  } catch (err) {
    alert("تعذّر بدء الفحص: " + err.message);
    $("run").disabled = false;
  }
  $("run").textContent = "ابدأ الفحص";
}

function attach(jobId) {
  currentJob = jobId;
  railType = null;
  $("idle").hidden = true;
  $("result").hidden = false;
  $("rail").hidden = false;
  $("dl-html").href = `/api/scan/${jobId}/report.html`;
  $("dl-json").href = `/api/scan/${jobId}/report.json`;
  primeRail(null);
  tick();
  poller = setInterval(tick, 1500);
}

function stopPolling() { if (poller) { clearInterval(poller); poller = null; } }

async function tick() {
  if (!currentJob) return;
  let job;
  try {
    const r = await fetch(`/api/scan/${currentJob}`);
    if (!r.ok) { stopPolling(); return; }
    job = await r.json();
  } catch { return; }

  render(job);
  if (job.status === "done" || job.status === "error") {
    stopPolling();
    $("run").disabled = false;
    loadHistory();
  }
}

/* ---------- telemetry rail ---------- */
function primeRail(targetType) {
  const relevant = catalog.filter(m =>
    !targetType || m.accepts.includes(targetType) || PIVOT_TYPES.includes(m.accepts[0]));
  $("rail-items").innerHTML = (relevant.length ? relevant : catalog).map(m =>
    `<div class="rail-item" data-mod="${m.name}">
       <span class="tick"></span>
       <span class="nm" title="${esc(m.description)}">${esc(m.title || m.name)}</span>
       <span class="rt">—</span>
     </div>`).join("");
}

function paintRail(job) {
  const reports = Object.fromEntries((job.payload.modules || []).map(m => [m.module, m]));
  const running = job.status === "running";
  $("rail-items").querySelectorAll(".rail-item").forEach(el => {
    const rep = reports[el.dataset.mod];
    el.className = "rail-item " + (rep ? rep.status : (running ? "running" : ""));
    el.querySelector(".rt").textContent = rep
      ? (rep.status === "not_configured" ? "غير مهيّأ" : `${rep.duration}s`)
      : (running ? "…" : "—");
    if (rep && (rep.note || rep.error)) el.title = rep.note || rep.error;
  });
  $("elapsed").textContent = `${(job.payload.elapsed || 0).toFixed(1)}s`;
}

/* ---------- render ---------- */
function render(job) {
  const p = job.payload || {}, s = p.summary || {}, c = s.counts || {};
  if (railType !== job.target_type) { railType = job.target_type; primeRail(railType); }
  paintRail(job);

  $("r-type").textContent = job.target_type + (job.status === "running" ? " · جارٍ الفحص" : "");
  $("r-target").textContent = job.target;
  $("r-meta").textContent = `${job.id} · ${(p.elapsed || 0).toFixed(1)}s · ${job.status}`;

  const score = s.exposure_score || 0;
  $("stats").innerHTML = [
    [score, "مؤشر الانكشاف /100", score > 50 ? "hot" : score > 20 ? "warm" : ""],
    [c.accounts || 0, "حساب مرتبط", ""],
    [c.breaches || 0, "تسريب", (c.breaches ? "hot" : "")],
    [c.names || 0, "اسم محتمل", ""],
    [c.corroborated || 0, "مؤكَّد من مصدرين+", ""],
    [c.findings || 0, "إجمالي النتائج", ""],
  ].map(([v, l, cls]) => `<div class="stat ${cls}"><b>${v}</b><span>${l}</span></div>`).join("");

  renderFindings(p.findings || []);
  renderLog(p.log || []);
  renderGraph(p.graph || { nodes: [], edges: [] });
  $("n-findings").textContent = (p.findings || []).length;
  $("n-nodes").textContent = ((p.graph || {}).nodes || []).length;
}

function renderFindings(findings) {
  if (!findings.length) {
    $("p-findings").innerHTML =
      '<div class="empty-state"><b>لا نتائج بعد</b>الوحدات ما زالت تعمل، أو لم يُعثر على شيء.</div>';
    return;
  }
  const groups = {};
  findings.forEach(f => (groups[f.category] ||= []).push(f));

  const html = CAT_ORDER.filter(k => groups[k]).map(k => {
    const items = groups[k].sort((a, b) =>
      (SEV[a.severity] ?? 3) - (SEV[b.severity] ?? 3) || b.confidence - a.confidence);
    return `<div class="group-head">${CATS[k] || k} <span style="color:var(--line)">/</span> ${items.length}</div>` +
      items.map(f => {
        const pct = Math.round((f.confidence ?? 1) * 100);
        return `<div class="finding">
          <span class="dot ${f.severity}"></span>
          <div>
            <div class="ttl">${esc(f.title)}</div>
            ${f.detail ? `<div class="det">${esc(f.detail)}</div>` : ""}
            ${f.url ? `<div class="det"><a href="${esc(f.url)}" target="_blank" rel="noopener nofollow">${esc(f.url)}</a></div>` : ""}
            <div class="src">${esc(f.module)}</div>
          </div>
          <div class="conf">
            <span class="bar ${pct < 70 ? "low" : ""}"><i style="width:${pct}%"></i></span>${pct}%
          </div>
        </div>`;
      }).join("");
  }).join("");
  $("p-findings").innerHTML = html;
}

function renderLog(log) {
  $("log").innerHTML = log.map(l =>
    `<div class="${l.level || "info"}"><span class="t">[${(l.t ?? 0).toFixed(1)}s]</span> ${esc(l.msg)}</div>`
  ).join("") || '<span style="color:var(--dim)">—</span>';
}

function renderGraph(g) {
  const el = $("graph");
  if (!window.cytoscape) {
    el.innerHTML = `<div style="padding:30px;color:var(--muted);font-size:13.5px">
      <b style="color:var(--ink);display:block;margin-bottom:6px">مكتبة الرسم لم تُحمَّل</b>
      Cytoscape يُجلب من CDN. إن كنت تشغّل الأداة بدون إنترنت، نزّل الملف مرة واحدة إلى
      <span class="mono">app/static/vendor/cytoscape.min.js</span> وحدّث الوسم في
      <span class="mono">index.html</span>. بقية التقرير يعمل طبيعياً.
    </div>`;
    return;
  }
  if (!g.nodes || !g.nodes.length) {
    el.innerHTML = '<p style="padding:26px;color:var(--muted)">لا توجد عقد بعد.</p>';
    return;
  }
  const signature = g.nodes.length + ":" + g.edges.length;
  if (cy && cy._sig === signature) return;   // avoid re-layout on every poll
  el.innerHTML = "";

  cy = cytoscape({
    container: el,
    elements: [...g.nodes, ...g.edges],
    layout: {
      name: "cose", animate: false, padding: 50, fit: true,
      nodeRepulsion: 14000, idealEdgeLength: 110, componentSpacing: 120,
      nodeOverlap: 24, gravity: 0.6, numIter: 1200,
    },
    style: [
      { selector: "node", style: {
          "background-color": (n) => n.data("seed") ? "#FFB020"
            : n.data("type") === "breach" ? "#F2555A"
            : n.data("confidence") < 0.7 ? "#38BDF8" : "#DCE3EA",
          "width": (n) => 15 + Math.min(n.data("degree") || 1, 9) * 3,
          "height": (n) => 15 + Math.min(n.data("degree") || 1, 9) * 3,
          "label": "data(label)", "font-size": 9,
          "font-family": "IBM Plex Mono, monospace",
          "color": "#6F8093", "text-valign": "bottom", "text-margin-y": 6 } },
      { selector: "edge", style: {
          "width": (e) => 0.5 + (e.data("confidence") || 0.5) * 2.2,
          "line-color": "#1E2833", "curve-style": "bezier", "opacity": 0.9 } },
      { selector: "node:selected", style: { "border-width": 2, "border-color": "#FFB020" } },
    ],
  });
  cy._sig = signature;
  cy.one("layoutstop", () => fitGraph());
  requestAnimationFrame(() => fitGraph());

  cy.on("tap", "node", (evt) => {
    const d = evt.target.data();
    $("node-card").hidden = false;
    $("node-card").innerHTML = `
      <h4>${esc(d.typeLabel)} — ${esc(d.full)}</h4>
      <div class="det" style="color:var(--muted);font-size:13px">
        الثقة ${Math.round(d.confidence * 100)}% · المصدر ${esc(d.source || "—")} ·
        روابط ${d.degree} · تأكيد من ${d.corroboration} مصدر
      </div>
      ${d.url ? `<div style="margin-top:6px"><a href="${esc(d.url)}" target="_blank" rel="noopener nofollow">${esc(d.url)}</a></div>` : ""}`;
  });
  cy.on("tap", (e) => { if (e.target === cy) $("node-card").hidden = true; });
}

/* ---------- tabs ---------- */
function fitGraph() {
  if (!cy) return;
  const el = $("graph");
  if (!el.offsetWidth) return;          // still hidden - nothing to fit into
  cy.resize();
  cy.fit(undefined, 45);
  if (cy.zoom() > 1.6) { cy.zoom(1.6); cy.center(); }
}

function wireTabs() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(b => {
        const on = b === btn;
        b.setAttribute("aria-selected", String(on));
        $(b.dataset.panel).hidden = !on;
      });
      if (btn.dataset.panel === "p-graph") fitGraph();
    });
  });
}

function fmtDate(ts) {
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, ch =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}
