/**
 * Dashboard page controller: statistics cards, charts and recent activity.
 * @module pages/dashboard
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import {
  renderCvssChart,
  renderMonthlyScansChart,
  renderSeverityChart,
} from '/components/charts.js';
import { cvssBadge, progressBar, severityBadge, statusPill } from '/components/badge-criticite.js';
import { setLoading } from '/components/modal.js';
import { toastError } from '/components/toast.js';
import { startVisiblePolling } from '/services/polling.js';
import { escapeHtml, formatDate, formatRelative, humanize } from '/utils/format.js';
 
/** Definition of the dashboard statistic cards. */
const CARDS = [
  { key: 'total_assets', label: 'Total assets', icon: 'fa-server', variant: '' },
  { key: 'total_vulnerabilities', label: 'Vulnerabilities', icon: 'fa-bug', variant: 'info' },
  { key: 'critical', label: 'Critical', icon: 'fa-skull-crossbones', variant: 'critical' },
  { key: 'high', label: 'High', icon: 'fa-triangle-exclamation', variant: 'high' },
  { key: 'medium', label: 'Medium', icon: 'fa-circle-exclamation', variant: 'medium' },
  { key: 'low', label: 'Low', icon: 'fa-circle-info', variant: 'low' },
  { key: 'running_scans', label: 'Running scans', icon: 'fa-spinner', variant: 'info' },
  { key: 'finished_scans', label: 'Finished scans', icon: 'fa-circle-check', variant: 'success' },
];
 
const statCards = document.querySelector('[data-role="stat-cards"]');
 
/**
 * Render the statistic cards.
 * @param {object} stats Dashboard counters.
 */
function renderStats(stats) {
  statCards.innerHTML = CARDS.map(
    (card) => `
      <div class="col-6 col-md-4 col-xl-3">
        <div class="stat-card">
          <div class="stat-card__icon ${card.variant ? `stat-card__icon--${card.variant}` : ''}">
            <i class="fa-solid ${card.icon}"></i>
          </div>
          <div>
            <div class="stat-card__value">${stats[card.key] ?? 0}</div>
            <div class="stat-card__label">${card.label}</div>
          </div>
        </div>
      </div>`,
  ).join('');
}
 
/**
 * Fill a table body with rows built from a dataset.
 * @param {string} selector Table selector.
 * @param {object[]} rows Dataset.
 * @param {function(object): string} template Row template.
 * @param {number} columns Column count used by the empty state.
 */
function fillTable(selector, rows, template, columns) {
  const body = document.querySelector(`${selector} tbody`);
  body.innerHTML = rows.length
    ? rows.map(template).join('')
    : `<tr><td colspan="${columns}" class="text-center text-muted py-4">No data</td></tr>`;
}
 
/**
 * Load the dashboard payload and render every widget.
 * @returns {Promise<object>} The dashboard payload.
 */
async function loadDashboard() {
  const data = await api.get('/dashboard');
  renderStats(data.stats);
 
  renderSeverityChart(document.querySelector('[data-role="chart-severity"]'), data.severity_distribution);
  renderCvssChart(document.querySelector('[data-role="chart-cvss"]'), data.cvss_distribution);
  renderMonthlyScansChart(document.querySelector('[data-role="chart-monthly"]'), data.monthly_scans);
 
  fillTable(
    '[data-role="table-assets"]',
    data.recent_assets,
    (asset) => `
      <tr>
        <td><a href="/asset-detail?id=${asset.id}">${escapeHtml(asset.hostname)}</a></td>
        <td>${escapeHtml(asset.ip_address)}</td>
        <td>${statusPill(asset.agent_status)}</td>
        <td>${formatRelative(asset.last_scan_at)}</td>
      </tr>`,
    4,
  );
 
  fillTable(
    '[data-role="table-vulns"]',
    data.recent_vulnerabilities,
    (vuln) => `
      <tr>
        <td><a href="/vulnerability-detail?id=${vuln.id}">${escapeHtml(vuln.cve_id)}</a></td>
        <td>${severityBadge(vuln.severity)}</td>
        <td>${cvssBadge(vuln.cvss_score)}</td>
        <td>${escapeHtml(vuln.package_name ?? '—')}</td>
      </tr>`,
    4,
  );
 
  fillTable(
    '[data-role="table-scans"]',
    data.recent_scans,
    (scan) => `
      <tr>
        <td><a href="/scan-detail?id=${scan.id}">${escapeHtml(scan.name)}</a></td>
        <td>${escapeHtml(humanize(scan.scanner))}</td>
        <td class="text-truncate" style="max-width: 260px">${escapeHtml(scan.target)}</td>
        <td>${statusPill(scan.status)}</td>
        <td style="min-width: 120px">${progressBar(scan.progress, scan.status)}</td>
        <td>${formatDate(scan.started_at)}</td>
      </tr>`,
    6,
  );
 
  return data;
}
 
await requireAuth();
await initLayout({ active: 'dashboard' });
 
setLoading(true);
try {
  await loadDashboard();
} catch (error) {
  toastError(error.message);
} finally {
  setLoading(false);
}
 
document.querySelector('[data-action="refresh"]').addEventListener('click', () => {
  loadDashboard().catch((error) => toastError(error.message));
});
 
document.addEventListener('vg:theme-changed', () => {
  loadDashboard().catch(() => {});
});
 
// Keep the dashboard fresh while the tab is visible.
startVisiblePolling(loadDashboard, { interval: 15000, immediate: false, onError: () => {} });