/**
 * Vulnerabilities page controller: search, filters, sorting and triage.
 * @module pages/vulnerabilities
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { cvssBadge, severityBadge, statusPill } from '/components/badge-criticite.js';
import { openModal, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { escapeHtml, humanize } from '/utils/format.js';
import { hasRole } from '/services/state.js';
 
const filters = document.querySelector('[data-role="filters"]');
const query = new URLSearchParams(window.location.search);
 
await requireAuth();
await initLayout({ active: 'vulnerabilities' });
 
// The header search box deep links into this page.
if (query.get('search')) filters.search.value = query.get('search');
if (query.get('severity')) filters.severity.value = query.get('severity');
 
const canTriage = hasRole('admin', 'soc_analyst', 'pentester');
 
/** @returns {object} Current filter values sent to the API. */
function filterParams() {
  const data = new FormData(filters);
  return {
    search: data.get('search') || undefined,
    severity: data.get('severity') || undefined,
    status: data.get('status') || undefined,
    min_cvss: data.get('min_cvss') || undefined,
    exploit_available: data.get('exploit_available') || undefined,
  };
}
 
const table = createServerTable({
  selector: '[data-role="vulns-table"]',
  endpoint: '/vulnerabilities',
  params: filterParams,
  searching: false,
  order: [[2, 'desc']],
  sortFields: { 0: 'cve_id', 1: 'severity', 2: 'cvss_score', 3: 'package_name' },
  columns: [
    {
      data: 'cve_id',
      render: (value, type, row) =>
        `<a href="/vulnerability-detail?id=${row.id}" class="fw-semibold">${escapeHtml(value)}</a>` +
        (row.exploit_available
          ? ' <i class="fa-solid fa-fire text-danger" title="Exploit available"></i>'
          : ''),
    },
    { data: 'severity', render: (value) => severityBadge(value) },
    { data: 'cvss_score', render: (value) => cvssBadge(value) },
    { data: 'package_name', render: (value) => escapeHtml(value ?? '—') },
    { data: 'installed_version', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    { data: 'fixed_version', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    {
      data: 'asset_hostname',
      orderable: false,
      render: (value, type, row) =>
        row.asset_id ? `<a href="/asset-detail?id=${row.asset_id}">${escapeHtml(value ?? '—')}</a>` : '—',
    },
    { data: 'status', orderable: false, render: (value) => statusPill(value) },
    {
      data: null,
      orderable: false,
      className: 'text-end',
      render: (value, type, row) => `
        <div class="btn-group btn-group-sm">
          <a class="btn btn-outline-secondary" href="/vulnerability-detail?id=${row.id}" title="Open">
            <i class="fa-solid fa-eye"></i></a>
          ${canTriage ? `<button class="btn btn-outline-primary" data-action="triage" data-id="${row.id}" data-status="${row.status}" title="Change status"><i class="fa-solid fa-list-check"></i></button>` : ''}
        </div>`,
    },
  ],
});
 
filters.addEventListener('submit', (event) => {
  event.preventDefault();
  table.ajax.reload();
});
 
document.querySelector('[data-role="vulns-table"]').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action="triage"]');
  if (!button) return;
  const id = Number(button.dataset.id);
  const current = button.dataset.status;
  const statuses = ['open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive'];
 
  await openModal({
    title: 'Update triage status',
    body: `
      <label class="form-label" for="triage-status">Status</label>
      <select class="form-select" id="triage-status">
        ${statuses
          .map((value) => `<option value="${value}" ${value === current ? 'selected' : ''}>${humanize(value)}</option>`)
          .join('')}
      </select>`,
    confirmLabel: 'Save',
    onConfirm: async (root) => {
      try {
        await api.patch(`/vulnerabilities/${id}`, { status: root.querySelector('#triage-status').value });
        toastSuccess('Status updated');
        table.ajax.reload(null, false);
        return true;
      } catch (error) {
        toastError(error.message);
        return false;
      }
    },
  });
});
 
document.querySelector('[data-action="export"]').addEventListener('click', async () => {
  try {
    await withLoading(() =>
      api.post('/reports', { name: 'Vulnerability export', format: 'csv', scope: 'all' }),
    );
    toastSuccess('CSV report generated, download it from the Reports page');
  } catch (error) {
    toastError(error.message);
  }
});