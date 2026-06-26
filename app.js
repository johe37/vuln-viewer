const PAGE_SIZE = 20;

let reportsIndex = [];
let currentReport = null;
let allRows = [];
let sortKey = null;
let sortDir = 1;
let page = 0;

const reportSelect = document.getElementById("reportSelect");
const tableBody = document.getElementById("tableBody");
const summary = document.getElementById("summary");
const search = document.getElementById("search");
const pagination = document.getElementById("pagination");

init();

async function init() {
  reportsIndex = await fetch("reports/index.json").then(r => r.json());

  reportSelect.innerHTML = reportsIndex
    .map(r => `<option value="${r}">${r}</option>`)
    .join("");

  reportSelect.addEventListener("change", loadReport);
  search.addEventListener("input", debounce(() => {
    page = 0;
    renderTable();
  }, 150));
  document.querySelectorAll("th").forEach(th =>
    th.addEventListener("click", () => {
      const key = th.textContent.trim().replace(/ [▲▼]$/, "");
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;
      page = 0;
      renderTable();
    })
  );

  loadReport();
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

async function loadReport() {
  const file = reportSelect.value;
  currentReport = await fetch(`reports/${file}`).then(r => r.json());
  allRows = extractResults(currentReport);

  renderSummary();
  renderTable();
}

function renderSummary() {
  const stats = calculateStats(allRows);

  summary.innerHTML = `
    <b>Total:</b> ${stats.total} |
    <b>Critical:</b> ${stats.critical} |
    <b>High:</b> ${stats.high} |
    <b>Medium:</b> ${stats.medium} |
    <b>Low:</b> ${stats.low}
  `;
}

function calculateStats(rows) {
  let stats = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  stats.total = rows.length;

  for (const r of rows) {
    const s = (r.Severity || "").toLowerCase();
    if (s.includes("critical")) stats.critical++;
    else if (s.includes("high")) stats.high++;
    else if (s.includes("medium")) stats.medium++;
    else if (s.includes("low")) stats.low++;
  }

  return stats;
}

function extractResults(data) {
  // Trivy rootfs format safe extraction
  let results = [];

  for (const r of data.Results || []) {
    if (!r.Vulnerabilities) continue;

    for (const v of r.Vulnerabilities) {
      results.push({
        Package: r.Target,
        Severity: v.Severity,
        CVE: v.VulnerabilityID,
        Installed: v.InstalledVersion,
        Fixed: v.FixedVersion || "-"
      });
    }
  }

  return results;
}

function renderTable() {
  const query = search.value.toLowerCase();
  let rows = allRows.filter(r =>
      r.Package.toLowerCase().includes(query) ||
      r.CVE.toLowerCase().includes(query)
    );

  if (sortKey) {
    const keyMap = {Severity: "Severity", Package: "Package", Installed: "Installed", Fixed: "Fixed", CVE: "CVE"};
    const k = keyMap[sortKey];
    const severityOrder = {critical: 0, high: 1, medium: 2, low: 3};
    rows.sort((a, b) => {
      let va = a[k], vb = b[k];
      if (k === "Severity") {
        va = severityOrder[va.toLowerCase()] ?? 99;
        vb = severityOrder[vb.toLowerCase()] ?? 99;
      } else {
        va = (va || "").toLowerCase();
        vb = (vb || "").toLowerCase();
      }
      return va < vb ? -sortDir : va > vb ? sortDir : 0;
    });
  }

  page = Math.min(page, Math.max(0, Math.ceil(rows.length / PAGE_SIZE) - 1));

  const start = page * PAGE_SIZE;
  const pageRows = rows.slice(start, start + PAGE_SIZE);

  const sortArrows = {Severity: "", Package: "", Installed: "", Fixed: "", CVE: ""};
  if (sortKey && sortArrows.hasOwnProperty(sortKey)) {
    sortArrows[sortKey] = sortDir === 1 ? " ▲" : " ▼";
  }

  document.querySelectorAll("th").forEach(th => {
    const key = th.textContent.trim().replace(/ [▲▼]$/, "");
    th.textContent = key + (sortArrows[key] || "");
  });

  tableBody.innerHTML = pageRows.map(r => `
    <tr>
      <td>${r.Severity}</td>
      <td>${r.Package}</td>
      <td>${r.Installed}</td>
      <td>${r.Fixed}</td>
      <td>${r.CVE}</td>
    </tr>
  `).join("");

  renderPagination(rows.length);
}

function renderPagination(total) {
  const totalPages = Math.ceil(total / PAGE_SIZE);
  if (totalPages <= 1) { pagination.innerHTML = ""; return; }

  const maxVisible = 9;
  let startPage = Math.max(0, page - Math.floor(maxVisible / 2));
  let endPage = Math.min(totalPages, startPage + maxVisible);
  if (endPage - startPage < maxVisible) startPage = Math.max(0, endPage - maxVisible);

  let html = "";
  if (page > 0) html += `<button data-page="0">«</button><button data-page="${page - 1}">‹</button>`;
  for (let i = startPage; i < endPage; i++) {
    html += `<button data-page="${i}"${i === page ? ' class="active"' : ""}>${i + 1}</button>`;
  }
  if (page < totalPages - 1) html += `<button data-page="${page + 1}">›</button><button data-page="${totalPages - 1}">»</button>`;
  pagination.innerHTML = html;
}

pagination.addEventListener("click", e => {
  const btn = e.target.closest("button");
  if (!btn) return;
  page = parseInt(btn.dataset.page, 10);
  renderTable();
});
