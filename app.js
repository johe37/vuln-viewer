let reportsIndex = [];
let currentReport = null;

const reportSelect = document.getElementById("reportSelect");
const tableBody = document.getElementById("tableBody");
const summary = document.getElementById("summary");
const search = document.getElementById("search");

init();

async function init() {
  reportsIndex = await fetch("reports/index.json").then(r => r.json());

  reportSelect.innerHTML = reportsIndex
    .map(r => `<option value="${r}">${r}</option>`)
    .join("");

  reportSelect.addEventListener("change", loadReport);
  search.addEventListener("input", renderTable);

  loadReport();
}

async function loadReport() {
  const file = reportSelect.value;
  currentReport = await fetch(`reports/${file}`).then(r => r.json());

  renderSummary();
  renderTable();
}

function renderSummary() {
  const stats = calculateStats(currentReport);

  summary.innerHTML = `
    <b>Packages:</b> ${stats.packages} |
    <b>Critical:</b> ${stats.critical} |
    <b>High:</b> ${stats.high} |
    <b>Medium:</b> ${stats.medium} |
    <b>Low:</b> ${stats.low}
  `;
}

function calculateStats(data) {
  let stats = {
    packages: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  const results = extractResults(data);
  stats.packages = results.length;

  for (const r of results) {
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
  const rows = extractResults(currentReport)
    .filter(r =>
      r.Package.toLowerCase().includes(query) ||
      r.CVE.toLowerCase().includes(query)
    );

  tableBody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.Severity}</td>
      <td>${r.Package}</td>
      <td>${r.Installed}</td>
      <td>${r.Fixed}</td>
      <td>${r.CVE}</td>
    </tr>
  `).join("");
}
