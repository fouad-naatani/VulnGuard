/**
 * Reports page controller: generation, history and downloads.
 * @module pages/reports
 */
 
import { api, getAccessToken, getBaseUrl } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { statusPill } from '/components/badge-criticite.js';
import { confirmDialog, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { escapeHtml, formatBytes, formatDate, humanize } from '/utils/format.js';
 
await requireAuth({ roles: ['admin', 'soc_analyst', 'pentester'] });
await initLayout({ active: 'reports' });
 
const form = document.querySelector('[data-role="report-form"]');
const scopeWrapper = document.querySelector('[data-role="scope-target-wrapper"]');
const scopeSelect = document.querySelector('#report-scope-id');
const correlationHint = document.querySelector('[data-role="correlation-hint"]');
 
const table = createServerTable({
  selector: '[data-role="reports-table"]',
  endpoint: '/reports',
  searching: false,
  columns: [
    { data: 'name', render: (value) => escapeHtml(value) },
    { data: 'format', orderable: false, render: (value) => escapeHtml(value.toUpperCase()) },
    {
      data: 'scope',
      orderable: false,
      render: (value, type, row) => escapeHtml(humanize(value) + (row.scope_id ? ` #${row.scope_id}` : '')),
    },
    {
      data: 'status',
      orderable: false,
      render: (value, type, row) =>
        statusPill(value) + (row.error_message ? ` <small class="text-danger">${escapeHtml(row.error_message)}</small>` : ''),
    },
    { data: 'file_size', orderable: false, render: (value) => formatBytes(value) },
    { data: 'created_at', orderable: false, render: (value) => formatDate(value) },
    {
      data: null,
      orderable: false,
      className: 'text-end',
      render: (value, type, row) => `
        <div class="btn-group btn-group-sm">
          <button class="btn btn-outline-primary" data-action="download" data-id="${row.id}"
                  ${row.status === 'ready' ? '' : 'disabled'} title="Download">
            <i class="fa-solid fa-download"></i></button>
          <button class="btn btn-outline-danger" data-action="delete" data-id="${row.id}" title="Delete">
            <i class="fa-solid fa-trash"></i></button>
        </div>`,
    },
  ],
});
 
/**
 * Populate the scope target selector with assets, scans, or correlation candidates.
 * @param {string} scope Selected scope.
 */
async function loadScopeTargets(scope) {
  correlationHint.classList.toggle('d-none', scope !== 'correlation');

  if (scope === 'all') {
    scopeWrapper.classList.add('d-none');
    return;
  }

  if (scope === 'correlation') {
    const candidates = await api.get('/reports/correlation/candidates');
    const options = [
      '<option value="">All correlated assets</option>',
      ...candidates.map(
        (item) =>
          `<option value="${item.id}">${escapeHtml(item.hostname)} — ${escapeHtml(item.ip_address)} ` +
          `(${item.matched_count} matched, ${item.critical_high_count} critical/high)</option>`,
      ),
    ];
    scopeSelect.innerHTML = options.join('');
    if (candidates.length === 0) {
      toastError('No asset currently has both Wazuh and Nessus findings yet — the report will be empty.');
    }
    scopeWrapper.classList.remove('d-none');
    return;
  }

  const endpoint = scope === 'asset' ? '/assets' : '/scans';
  const response = await api.get(endpoint, { page_size: 200 });
  scopeSelect.innerHTML = response.items
    .map(
      (item) =>
        `<option value="${item.id}">${escapeHtml(item.hostname ?? item.name)}${item.target ? ` — ${escapeHtml(item.target)}` : ''}</option>`,
    )
    .join('');
  scopeWrapper.classList.remove('d-none');
}
 
form.scope.addEventListener('change', (event) => {
  loadScopeTargets(event.target.value).catch((error) => toastError(error.message));
});
 
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const nameValid = form.name.value.trim().length > 0;
  form.name.classList.toggle('is-invalid', !nameValid);
  if (!nameValid) return;
 
  const noTargetScope = form.scope.value === 'all' || (form.scope.value === 'correlation' && !scopeSelect.value);

  try {
    const report = await withLoading(() =>
      api.post('/reports', {
        name: form.name.value.trim(),
        format: form.format.value,
        scope: form.scope.value,
        scope_id: noTargetScope ? null : Number(scopeSelect.value),
      }),
    );
    if (report.status === 'ready') {
      toastSuccess('Report generated');
    } else {
      toastError(report.error_message ?? 'Report generation failed');
    }
    form.reset();
    scopeWrapper.classList.add('d-none');
    correlationHint.classList.add('d-none');
    table.ajax.reload(null, false);
  } catch (error) {
    toastError(error.message);
  }
});
 
/**
 * Download a report through an authenticated request.
 * @param {number} id Report identifier.
 */
async function downloadReport(id) {
  const response = await fetch(`${getBaseUrl()}/reports/${id}/download`, {
    headers: { Authorization: `Bearer ${getAccessToken()}` },
  });
  if (!response.ok) throw new Error(`Download failed (${response.status})`);
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = disposition.match(/filename="?([^";]+)"?/);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = match?.[1] ?? `report-${id}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
 
document.querySelector('[data-role="reports-table"]').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = Number(button.dataset.id);
  try {
    if (button.dataset.action === 'download') {
      await withLoading(() => downloadReport(id));
    } else {
      const confirmed = await confirmDialog({ message: 'Delete this report?' });
      if (!confirmed) return;
      await withLoading(() => api.delete(`/reports/${id}`));
      toastSuccess('Report deleted');
      table.ajax.reload(null, false);
    }
  } catch (error) {
    toastError(error.message);
  }
});