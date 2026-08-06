"use strict";

const $ = (id) => document.getElementById(id);
const CATS = {
  identity: "الهوية", accounts: "الحسابات", breaches: "التسريبات",
  phone: "الهاتف", infra: "البنية التحتية", misc: "أخرى",
};
const CAT_ORDER = ["breaches", "identity", "accounts", "phone", "infra", "misc"];
const SEV = { high: 0, notable: 1, info: 2 };
const HIST_KEY = "osint-lite-history";

let cy = null, catalog = [], lastResult = null;

init();

async function init() {
  wireForm();
  wireTabs();
  await loadCatalog();
  renderHistory();
}

async function loadCatalog() {
  try {
    const r = await fetch("/api/modules");
    catalog = (await r.json()).modules || [];
  } catch {
    catalog = [];
  }
}

/* ---------- storage (best-effort; private mode can block it) ---------- */
function readHistory() {
  try { return JSON.parse(localStorage.getItem(HIST_KEY) || "[]"); }
  catch { return []; }
}
function pushHistory(entry) {
  try {
    const list = readHistory().filter(h => h.target !== entry.target);
    list.unshift(entry);
    localStorage.setItem(HIST_KEY, JSON.stringify(list.slice(0, 8)));
  } catch { /* storage unavailable - history is a nicety, not a requirement */ }
  renderHistory();
}
function renderHistory() {
  const list = readHistory();
  $("history").innerHTML = list.length
    ? list.map((h, i) => `<a href="#" data-i="${i}">${esc(h.target)}
        <span class="mono">${h.findings} نتيجة · ${fmtDate(h.at)}</span></a>`).join("")
    : '<span style="color:var(--dim);font-size:12px">لا شيء بعد</span>';
  $("history").querySelectorAll("a").forEach(a =>
    a.addEventListener("click", (e) => {
      e.preventDefault();
      const h = readHistory()[+a.dataset.i];
      if (h?.result) { lastResult = h.result; show(h.result); }
    }));
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
    $("result").hidden = true; $("idle").hidden = false; $("rail").hidden = true;
    target.focus();
  });
  $("print").addEventListener("click", () => {
    if (!lastResult) return;
    document.querySelectorAll(".panel").forEach(p => { p.hidden = false; });
    fitGraph();
    setTimeout(() => window.print(), 350);
  });
  $("dl-json").addEventListener("click", () => {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `osint-${lastResult.target.replace(/[^a-z0-9._@-]/gi, "_")}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
}

function clearResult() {
  lastResult = null;
  if (cy) { try { cy.destroy(); } catch { /* already gone */ } cy = null; }
  $("err-slot").innerHTML = "";
  $("stats").innerHTML = "";
  $("p-findings").innerHTML = "";
  $("log").innerHTML = "";
  $("graph").innerHTML = "";
  $("node-card").hidden = true;
  $("n-findings").textContent = "0";
  $("n-nodes").textContent = "0";
}

async function start() {
  const target = $("target").value.trim();
  const run = $("run");
  run.disabled = true;
  run.innerHTML = '<span class="spinner"></span>جارٍ الفحص…';

  $("idle").hidden = true; $("result").hidden = false; $("rail").hidden = false;
  clearResult();
  primeRail($("ttype").value === "auto" ? null : $("ttype").value, true);
  $("r-target").textContent = target;
  $("r-type").textContent = "جارٍ الفحص";
  $("r-meta").textContent = "—";
  $("elapsed").textContent = "…";

  const t0 = performance.now();
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target, target_type: $("ttype").value, pivot: $("pivot").checked,
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    lastResult = data;
    show(data);
    pushHistory({ target, at: Date.now() / 1000, findings: data.findings.length, result: data });
  } catch (err) {
    clearResult();
    $("err-slot").innerHTML = `<div class="err"><b>تعذّر إكمال الفحص</b><br>${esc(err.message)}</div>`;
    $("r-type").textContent = "فشل";
    $("r-meta").textContent = `${((performance.now() - t0) / 1000).toFixed(1)}s`;
    $("elapsed").textContent = "—";
  }
  run.disabled = false;
  run.textContent = "ابدأ الفحص";
}

/* ---------- telemetry rail ---------- */
function primeRail(targetType, running) {
  const pivots = targetType === "email" ? ["domain"] : [];
  const rel = catalog.filter(m => !targetType || m.accepts.includes(targetType)
    || m.accepts.some(a => pivots.includes(a)));
  $("rail-items").innerHTML = (rel.length ? rel : catalog).map(m =>
    `<div class="rail-item ${running ? "running" : ""}" data-mod="${m.name}">
       <span class="tick"></span><span class="nm">${esc(m.title)}</span>
       <span class="rt">${running ? "…" : "—"}</span>
     </div>`).join("");
}

function paintRail(data) {
  primeRail(data.target_type, false);
  const reports = Object.fromEntries((data.modules || []).map(m => [m.module, m]));
  $("rail-items").querySelectorAll(".rail-item").forEach(el => {
    const rep = reports[el.dataset.mod];
    el.className = "rail-item " + (rep ? rep.status : "");
    el.querySelector(".rt").textContent = rep ? `${rep.duration}s` : "—";
    if (rep && (rep.note || rep.error)) el.title = rep.note || rep.error;
  });
  $("elapsed").textContent = `${(data.elapsed || 0).toFixed(1)}s`;
}

/* ---------- render ---------- */
function show(data) {
  $("idle").hidden = true; $("result").hidden = false; $("rail").hidden = false;
  lastResult = data;
  paintRail(data);

  const s = data.summary || {}, c = s.counts || {};
  $("r-type").textContent = data.target_type;
  $("r-target").textContent = data.target;
  $("r-meta").textContent = `${(data.elapsed || 0).toFixed(1)}s · ${(data.modules || []).length} وحدة`;

  const score = s.exposure_score || 0;
  $("stats").innerHTML = [
    [score, "مؤشر الانكشاف /100", score > 50 ? "hot" : score > 20 ? "warm" : ""],
    [c.accounts || 0, "حساب مرتبط", ""],
    [c.breaches || 0, "تسريب", c.breaches ? "hot" : ""],
    [c.names || 0, "اسم محتمل", ""],
    [c.corroborated || 0, "مؤكَّد من مصدرين+", ""],
    [c.findings || 0, "إجمالي النتائج", ""],
  ].map(([v, l, cls]) => `<div class="stat ${cls}"><b>${v}</b><span>${l}</span></div>`).join("");

  renderFindings(data.findings || []);
  renderLog(data.log || []);
  renderGraph(data.graph || { nodes: [], edges: [] });
  $("n-findings").textContent = (data.findings || []).length;
  $("n-nodes").textContent = ((data.graph || {}).nodes || []).length;
}

function renderFindings(findings) {
  if (!findings.length) {
    $("p-findings").innerHTML =
      '<div class="empty-state"><b>لا نتائج</b>لم تعثر أي وحدة على شيء لهذا الهدف.</div>';
    return;
  }
  const groups = {};
  findings.forEach(f => (groups[f.category] ||= []).push(f));

  $("p-findings").innerHTML = CAT_ORDER.filter(k => groups[k]).map(k => {
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
          <div class="conf"><span class="bar ${pct < 70 ? "low" : ""}"><i style="width:${pct}%"></i></span>${pct}%</div>
        </div>`;
      }).join("");
  }).join("");
}

function renderLog(log) {
  $("log").innerHTML = log.map(l =>
    `<div class="${l.level || "info"}"><span class="t">[${(l.t ?? 0).toFixed(1)}s]</span> ${esc(l.msg)}</div>`
  ).join("") || '<span style="color:var(--dim)">—</span>';
}

function renderGraph(g) {
  const el = $("graph");
  if (!window.cytoscape) {
    el.innerHTML = '<div style="padding:30px;color:var(--muted)">مكتبة الرسم لم تُحمَّل.</div>';
    return;
  }
  if (!g.nodes || !g.nodes.length) {
    el.innerHTML = '<p style="padding:26px;color:var(--muted)">لا توجد عقد لعرضها.</p>';
    return;
  }
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
  cy.one("layoutstop", () => fitGraph());
  requestAnimationFrame(() => fitGraph());

  cy.on("tap", "node", (evt) => {
    const d = evt.target.data();
    $("node-card").hidden = false;
    $("node-card").innerHTML = `
      <h4>${esc(d.typeLabel)} — ${esc(d.full)}</h4>
      <div style="color:var(--muted);font-size:13px">
        الثقة ${Math.round(d.confidence * 100)}% · المصدر ${esc(d.source || "—")} ·
        روابط ${d.degree} · تأكيد من ${d.corroboration} مصدر
      </div>
      ${d.url ? `<div style="margin-top:6px"><a href="${esc(d.url)}" target="_blank" rel="noopener nofollow">${esc(d.url)}</a></div>` : ""}`;
  });
  cy.on("tap", (e) => { if (e.target === cy) $("node-card").hidden = true; });
}

function fitGraph() {
  if (!cy) return;
  const el = $("graph");
  if (!el.offsetWidth) return;
  cy.resize();
  cy.fit(undefined, 45);
  if (cy.zoom() > 1.6) { cy.zoom(1.6); cy.center(); }
}

/* ---------- tabs ---------- */
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
  const d = new Date(ts * 1000), p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, ch =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}
