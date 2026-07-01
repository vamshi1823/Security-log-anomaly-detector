// Security Log Anomaly Detector - Dashboard logic
// Vanilla JS, no frameworks - talks to the Flask API endpoints.

let currentPage = 1;
let currentFilter = "all";
const PAGE_SIZE = 25;

async function loadStats() {
  const res = await fetch("/api/stats");
  const data = await res.json();
  document.getElementById("statTotal").textContent = data.total_logs.toLocaleString();
  document.getElementById("statAnomalies").textContent = data.anomalies_detected.toLocaleString();
  document.getElementById("statRate").textContent = data.anomaly_rate + "%";
  document.getElementById("statUsers").textContent = data.unique_users.toLocaleString();
}

async function loadLogs() {
  const tbody = document.getElementById("logsBody");
  tbody.innerHTML = `<tr><td colspan="9" class="loading-row">Loading logs&hellip;</td></tr>`;

  const params = new URLSearchParams({
    page: currentPage,
    page_size: PAGE_SIZE,
    filter: currentFilter,
  });
  const res = await fetch(`/api/logs?${params}`);
  const data = await res.json();

  if (data.records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="loading-row">No records found.</td></tr>`;
    return;
  }

  tbody.innerHTML = data.records.map(row => `
    <tr>
      <td>${formatTimestamp(row.timestamp)}</td>
      <td>${row.user_id}</td>
      <td>${row.source_ip}</td>
      <td>${row.country}</td>
      <td>${row.event_type}</td>
      <td>${row.bytes_transferred.toLocaleString()}</td>
      <td>${row.failed_logins_last_hour}</td>
      <td>${row.anomaly_score.toFixed(3)}</td>
      <td><span class="badge ${row.predicted}">${row.predicted}</span></td>
    </tr>
  `).join("");

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  document.getElementById("pageIndicator").textContent = `Page ${currentPage} of ${totalPages}`;
  document.getElementById("prevPage").disabled = currentPage <= 1;
  document.getElementById("nextPage").disabled = currentPage >= totalPages;
}

function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function setupFilters() {
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      currentPage = 1;
      loadLogs();
    });
  });
}

function setupPagination() {
  document.getElementById("prevPage").addEventListener("click", () => {
    if (currentPage > 1) { currentPage--; loadLogs(); }
  });
  document.getElementById("nextPage").addEventListener("click", () => {
    currentPage++; loadLogs();
  });
}

function setupScoreForm() {
  const form = document.getElementById("scoreForm");
  const resultBox = document.getElementById("scoreResult");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const payload = {
      event_type: fd.get("event_type"),
      bytes_transferred: Number(fd.get("bytes_transferred")),
      failed_logins_last_hour: Number(fd.get("failed_logins_last_hour")),
      hour_of_day: Number(fd.get("hour_of_day")),
      is_foreign_rare: fd.get("is_foreign_rare") ? 1 : 0,
      session_duration_min: 10,
    };

    const res = await fetch("/api/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    resultBox.className = `score-result show ${data.prediction}`;
    resultBox.textContent = data.prediction === "anomaly"
      ? `⚠ Flagged as ANOMALY (score: ${data.anomaly_score})`
      : `✓ Classified as NORMAL (score: ${data.anomaly_score})`;
  });
}

document.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadLogs();
  setupFilters();
  setupPagination();
  setupScoreForm();
});
