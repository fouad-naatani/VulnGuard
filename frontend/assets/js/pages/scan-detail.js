/**
 * Scan detail page controller with live log and progress polling.
 * @module pages/scan-detail
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { cvssBadge, progressBar, severityBadge, statusPill } from '/components/badge-criticite.js';
import { confirmDialog, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { startPolling } from '/services/polling.js';
import { escapeHtml, formatDate, formatDuration, humanize } from '/utils/format.js';
import { hasRole, pushNotification } from '/services/state.js';
 
const scanId = Number(new URLSearchParams(window.location.search).get('id'));
const TERMINAL_STATUSES = ['completed', 'failed', 'cancelled'];
 
await requireAuth({ roles: ['admin', 'soc_analyst', 'pentester'] });
await initLayout({ active: 'scans' });
 
if (!Number.isFinite(scanId) || scanId <= 0) {
  toastError('Missing scan identifier');
  throw new Error('Missing scan identifier');
}
 
const logConsole = document.querySelector('[data-role="logs"]');
const statsRow = document.querySelector('[data-role="scan-stats"]');
let previousStatus = null;
 
/**
 * Render the scan header, counters, progress bar and logs.
 * @param {object} scan Scan payload.
 */
function render(scan) {
  document.querySelector('[data-role="breadcrumb"]').textContent = scan.name;
  document.querySelector('[data-role="scan-name"]').textContent = scan.name;
  document.querySelector('[data-role="scan-target"]').textContent =
    `${humanize(scan.scanner)} · ${scan.target}`;
  document.title = `${scan.name} · VulnGuard`;
 
  statsRow.innerHTML = [
    { label: 'Status', value: humanize(scan.status), icon: 'fa-circle-play', variant: '' },
    { label: 'Findings', value: scan.vulnerability_count, icon: 'fa-bug', variant: 'critical' },
    { label: 'Packages', value: scan.packages_found, icon: 'fa-cubes', variant: 'info' },
    { label: 'Duration', value: formatDuration(scan.duration_seconds), icon: 'fa-stopwatch', variant: 'success' },
    { label: 'Started', value: formatDate(scan.started_at), icon: 'fa-play', variant: '' },
    { label: 'Finished', value: formatDate(scan.finished_at), icon: 'fa-flag-checkered', variant: 'success' },
  ]
    .map(
      (card) => `
        <div class="col-6 col-xl-2">
          <div class="stat-card">
            <div class="stat-card__icon ${card.variant ? `stat-card__icon--${card.variant}` : ''}">
              <i class="fa-solid ${card.icon}"></i>
            </div>
            <div>
              <div class="stat-card__value" style="font-size:1rem">${escapeHtml(String(card.value))}</div>
              <div class="stat-card__label">${card.label}</div>
            </div>
          </div>
        </div>`,
    )
    .join('');
 
  document.querySelector('[data-role="progress-bar"]').innerHTML = progressBar(scan.progress, scan.status);
  document.querySelector('[data-role="progress-value"]').textContent = `${scan.progress} %`;
  document.querySelector('[data-role="progress-label"]').innerHTML = statusPill(scan.status);
 
  document.querySelector('[data-role="log-count"]').textContent = scan.logs.length;
  const atBottom = logConsole.scrollTop + logConsole.clientHeight >= logConsole.scrollHeight - 24;
  logConsole.innerHTML = scan.logs.length
    ? scan.logs
        .map(
          (log) =>
            `<div class="log-console__line log-console__line--${escapeHtml(log.level)}">` +
            `<span class="text-muted">${formatDate(log.created_at)}</span> ` +
            `[${escapeHtml(log.level.toUpperCase())}] ${escapeHtml(log.message)}</div>`,
        )
        .join('')
    : '<div class="text-muted">No log line yet.</div>';
  if (atBottom) logConsole.scrollTop = logConsole.scrollHeight;
 
  const running = !TERMINAL_STATUSES.includes(scan.status);
  document.querySelector('[data-action="start"]').disabled = running;
  document.querySelector('[data-action="stop"]').disabled = !running;
 
  if (scan.error_message) {
    document.querySelector('[data-role="scan-target"]').innerHTML +=
      ` <span class="text-danger">— ${escapeHtml(scan.error_message)}</span>`;
  }
}
 
const resultsTable = createServerTable({
  selector: '[data-role="scan-vulns"]',
  endpoint: '/vulnerabilities',
  params: () => ({ scan_id: scanId }),
  pageLength: 10,
  order: [[2, 'desc']],
  sortFields: { 0: 'cve_id', 2: 'cvss_score', 3: 'package_name' },
  columns: [
    {
      data: 'cve_id',
      render: (value, type, row) => `<a href="/vulnerability-detail?id=${row.id}">${escapeHtml(value)}</a>`,
    },
    { data: 'severity', orderable: false, render: (value) => severityBadge(value) },
    { data: 'cvss_score', render: (value) => cvssBadge(value) },
    { data: 'package_name', render: (value) => escapeHtml(value ?? '—') },
    { data: 'installed_version', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    { data: 'fixed_version', orderable: false, render: (value) => escapeHtml(value ?? '—') },
  ],
});
 
if (hasRole('admin')) document.querySelector('[data-action="delete"]').classList.remove('d-none');
 
/**
 * Fetch the scan and refresh the view.
 * @returns {Promise<object>} The scan payload.
 */
async function refresh() {
  const scan = await api.get(`/scans/${scanId}`);
  render(scan);
  if (previousStatus && previousStatus !== scan.status && TERMINAL_STATUSES.includes(scan.status)) {
    resultsTable.ajax.reload(null, false);
    pushNotification({
      title: `Scan ${scan.status}`,
      message: `${scan.name} finished with ${scan.vulnerability_count} findings`,
      level: scan.status === 'completed' ? 'success' : 'warning',
    });
  }
  previousStatus = scan.status;
  return scan;
}
 
await withLoading(refresh).catch((error) => toastError(error.message));
 
// Poll every 5 seconds and stop automatically once the scan reaches a final state.
startPolling(refresh, {
  interval: 5000,
  immediate: false,
  until: (scan) => TERMINAL_STATUSES.includes(scan.status),
  onError: () => {},
});
 
document.querySelector('[data-action="start"]').addEventListener('click', async () => {
  try {
    await withLoading(() => api.post(`/scans/${scanId}/start`));
    toastSuccess('Scan started');
    startPolling(refresh, {
      interval: 5000,
      until: (scan) => TERMINAL_STATUSES.includes(scan.status),
      onError: () => {},
    });
  } catch (error) {
    toastError(error.message);
  }
});
 
document.querySelector('[data-action="stop"]').addEventListener('click', async () => {
  try {
    await withLoading(() => api.post(`/scans/${scanId}/stop`));
    toastSuccess('Stop requested');
    await refresh();
  } catch (error) {
    toastError(error.message);
  }
});
 
document.querySelector('[data-action="delete"]').addEventListener('click', async () => {
  const confirmed = await confirmDialog({ message: 'Delete this scan and its findings?' });
  if (!confirmed) return;
  try {
    await withLoading(() => api.delete(`/scans/${scanId}`));
    window.location.href = '/scans';
  } catch (error) {
    toastError(error.message);
  }
});