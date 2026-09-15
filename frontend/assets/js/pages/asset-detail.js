/**
 * Asset detail page controller.
 * @module pages/asset-detail
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { cvssBadge, severityBadge, statusPill, tagChips } from '/components/badge-criticite.js';
import { openModal, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { escapeHtml, formatDate, formatDuration, humanize } from '/utils/format.js';
import { hasRole } from '/services/state.js';
 
const assetId = Number(new URLSearchParams(window.location.search).get('id'));
 
await requireAuth();
await initLayout({ active: 'assets' });
 
if (!Number.isFinite(assetId) || assetId <= 0) {
  toastError('Missing asset identifier');
  throw new Error('Missing asset identifier');
}
 
const asset = await withLoading(() => api.get(`/assets/${assetId}`)).catch((error) => {
  toastError(error.message);
  throw error;
});
 
document.querySelector('[data-role="breadcrumb"]').textContent = asset.hostname;
document.querySelector('[data-role="asset-hostname"]').textContent = asset.hostname;
document.querySelector('[data-role="asset-subtitle"]').textContent =
  `${asset.ip_address} · ${asset.operating_system ?? 'Unknown OS'}`;
document.title = `${asset.hostname} · VulnGuard`;
 
document.querySelector('[data-role="asset-stats"]').innerHTML = [
  { label: 'Findings', value: asset.vulnerability_count, icon: 'fa-bug', variant: 'info' },
  { label: 'Critical', value: asset.critical_count, icon: 'fa-skull-crossbones', variant: 'critical' },
  { label: 'Agent', value: humanize(asset.agent_status), icon: 'fa-satellite-dish', variant: '' },
  { label: 'Last scan', value: formatDate(asset.last_scan_at), icon: 'fa-clock', variant: 'success' },
]
  .map(
    (card) => `
      <div class="col-6 col-xl-3">
        <div class="stat-card">
          <div class="stat-card__icon ${card.variant ? `stat-card__icon--${card.variant}` : ''}">
            <i class="fa-solid ${card.icon}"></i>
          </div>
          <div>
            <div class="stat-card__value" style="font-size:1.1rem">${escapeHtml(String(card.value))}</div>
            <div class="stat-card__label">${card.label}</div>
          </div>
        </div>
      </div>`,
  )
  .join('');
 
document.querySelector('[data-role="asset-info"]').innerHTML = [
  ['Hostname', escapeHtml(asset.hostname)],
  ['IP address', escapeHtml(asset.ip_address)],
  ['Operating system', escapeHtml(asset.operating_system ?? '—')],
  ['Owner', escapeHtml(asset.owner ?? '—')],
  ['Tags', tagChips(asset.tags)],
  ['Agent status', statusPill(asset.agent_status)],
  ['Description', escapeHtml(asset.description ?? '—')],
  ['Created', formatDate(asset.created_at)],
]
  .map(([label, value]) => `<dt class="col-5 text-muted fw-normal">${label}</dt><dd class="col-7">${value}</dd>`)
  .join('');
 
createServerTable({
  selector: '[data-role="asset-vulns"]',
  endpoint: '/vulnerabilities',
  params: () => ({ asset_id: assetId }),
  pageLength: 10,
  searching: true,
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
    { data: 'fixed_version', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    { data: 'status', orderable: false, render: (value) => statusPill(value) },
  ],
});
 
createServerTable({
  selector: '[data-role="asset-scans"]',
  endpoint: '/scans',
  params: () => ({ asset_id: assetId }),
  pageLength: 10,
  searching: false,
  columns: [
    {
      data: 'name',
      render: (value, type, row) => `<a href="/scan-detail?id=${row.id}">${escapeHtml(value)}</a>`,
    },
    { data: 'scanner', orderable: false, render: (value) => escapeHtml(humanize(value)) },
    { data: 'status', orderable: false, render: (value) => statusPill(value) },
    { data: 'vulnerability_count', orderable: false },
    { data: 'started_at', orderable: false, render: (value) => formatDate(value) },
    { data: 'duration_seconds', orderable: false, render: (value) => formatDuration(value) },
  ],
});
 
if (hasRole('admin', 'soc_analyst', 'pentester')) {
  const scanButton = document.querySelector('[data-action="scan-asset"]');
  scanButton.classList.remove('d-none');
  scanButton.addEventListener('click', async () => {
    await openModal({
      title: `Scan ${asset.hostname}`,
      body: `
        <form data-role="scan-form">
          <div class="mb-3">
            <label class="form-label" for="scan-target">Target</label>
            <input class="form-control" id="scan-target" name="target"
                   value="${escapeHtml(asset.hostname)}" required>
            <small class="text-muted">Container image reference or filesystem path for Trivy.</small>
          </div>
          <div class="mb-0">
            <label class="form-label" for="scan-scanner">Scanner</label>
            <select class="form-select" id="scan-scanner" name="scanner">
              <option value="TRIVY">Trivy</option>
              <option value="WAZUH">Wazuh</option>
              <option value="NESSUS">Nessus</option>

            </select>
          </div>
        </form>`,
      confirmLabel: 'Start scan',
      onConfirm: async (root) => {
        const form = root.querySelector('[data-role="scan-form"]');
        try {
          const scan = await api.post('/scans', {
            name: `Scan ${asset.hostname}`,
            scanner: form.scanner.value,
            target: form.target.value.trim(),
            asset_id: assetId,
            start_immediately: true,
          });
          toastSuccess('Scan started');
          window.location.href = `/scan-detail?id=${scan.id}`;
          return true;
        } catch (error) {
          toastError(error.message);
          return false;
        }
      },
    });
  });
}
 
document.querySelector('[data-action="export"]').addEventListener('click', async () => {
  try {
    const report = await withLoading(() =>
      api.post('/reports', {
        name: `Asset ${asset.hostname}`,
        format: 'pdf',
        scope: 'asset',
        scope_id: assetId,
      }),
    );
    toastSuccess('Report generated, find it on the Reports page');
    window.location.href = `/reports?highlight=${report.id}`;
  } catch (error) {
    toastError(error.message);
  }
});