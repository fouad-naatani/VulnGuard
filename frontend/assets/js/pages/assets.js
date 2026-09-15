/**
 * Assets page controller: CRUD, filters and server side pagination.
 * @module pages/assets
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { statusPill, tagChips } from '/components/badge-criticite.js';
import { confirmDialog, openModal, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { escapeHtml, formatRelative, humanize } from '/utils/format.js';
import { isHostname, isIpAddress } from '/utils/validators.js';
import { hasRole } from '/services/state.js';
 
const filters = document.querySelector('[data-role="filters"]');
 
/** @returns {object} Current filter values sent to the API. */
function filterParams() {
  const data = new FormData(filters);
  return {
    agent_status: data.get('agent_status') || undefined,
    tag: data.get('tag') || undefined,
    search: data.get('search') || undefined,
  };
}
 
/**
 * Build the asset form markup used by the create and edit modals.
 * @param {object} [asset] Existing asset when editing.
 * @returns {string} Form markup.
 */
function assetForm(asset = {}) {
  return `
    <form novalidate data-role="asset-form">
      <div class="row g-3">
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-hostname">Hostname *</label>
          <input class="form-control" id="asset-hostname" name="hostname" required
                 value="${escapeHtml(asset.hostname ?? '')}">
          <div class="invalid-feedback">Invalid hostname</div>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-ip">IP address *</label>
          <input class="form-control" id="asset-ip" name="ip_address" required
                 value="${escapeHtml(asset.ip_address ?? '')}">
          <div class="invalid-feedback">Invalid IP address</div>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-os">Operating system</label>
          <input class="form-control" id="asset-os" name="operating_system"
                 value="${escapeHtml(asset.operating_system ?? '')}">
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-owner">Owner</label>
          <input class="form-control" id="asset-owner" name="owner"
                 value="${escapeHtml(asset.owner ?? '')}">
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-tags">Tags (comma separated)</label>
          <input class="form-control" id="asset-tags" name="tags"
                 value="${escapeHtml((asset.tags ?? []).join(', '))}">
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="asset-agent">Agent status</label>
          <select class="form-select" id="asset-agent" name="agent_status">
            ${['online', 'offline', 'never_connected']
              .map(
                (value) =>
                  `<option value="${value}" ${asset.agent_status === value ? 'selected' : ''}>${humanize(value)}</option>`,
              )
              .join('')}
          </select>
        </div>
        <div class="col-12">
          <label class="form-label" for="asset-description">Description</label>
          <textarea class="form-control" id="asset-description" name="description" rows="2">${escapeHtml(asset.description ?? '')}</textarea>
        </div>
      </div>
    </form>`;
}
 
/**
 * Read and validate the asset form.
 * @param {HTMLElement} root Modal root element.
 * @returns {?object} Payload, or null when invalid.
 */
function readAssetForm(root) {
  const form = root.querySelector('[data-role="asset-form"]');
  const hostname = form.hostname;
  const ip = form.ip_address;
  const hostnameValid = isHostname(hostname.value);
  const ipValid = isIpAddress(ip.value);
  hostname.classList.toggle('is-invalid', !hostnameValid);
  ip.classList.toggle('is-invalid', !ipValid);
  if (!hostnameValid || !ipValid) return null;
 
  return {
    hostname: hostname.value.trim(),
    ip_address: ip.value.trim(),
    operating_system: form.operating_system.value.trim() || null,
    owner: form.owner.value.trim() || null,
    tags: form.tags.value
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean),
    agent_status: form.agent_status.value,
    description: form.description.value.trim() || null,
  };
}
 
await requireAuth();
await initLayout({ active: 'assets' });
 
const canEdit = hasRole('admin', 'soc_analyst', 'pentester');
const canDelete = hasRole('admin');
if (canEdit) document.querySelector('[data-action="create-asset"]').classList.remove('d-none');
 
const table = createServerTable({
  selector: '[data-role="assets-table"]',
  endpoint: '/assets',
  params: filterParams,
  searching: false,
  order: [[0, 'asc']],
  sortFields: { 0: 'hostname', 1: 'ip_address', 7: 'last_scan_at' },
  columns: [
    {
      data: 'hostname',
      render: (value, type, row) =>
        `<a href="/asset-detail?id=${row.id}" class="fw-semibold">${escapeHtml(value)}</a>`,
    },
    { data: 'ip_address', render: (value) => escapeHtml(value) },
    { data: 'operating_system', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    { data: 'owner', orderable: false, render: (value) => escapeHtml(value ?? '—') },
    { data: 'tags', orderable: false, render: (value) => tagChips(value) },
    { data: 'agent_status', orderable: false, render: (value) => statusPill(value) },
    {
      data: 'vulnerability_count',
      orderable: false,
      render: (value, type, row) =>
        `<span class="fw-semibold">${value}</span>` +
        (row.critical_count
          ? ` <span class="severity-badge severity-badge--critical">${row.critical_count}</span>`
          : ''),
    },
    { data: 'last_scan_at', render: (value) => formatRelative(value) },
    {
      data: null,
      orderable: false,
      className: 'text-end',
      render: (value, type, row) => `
        <div class="btn-group btn-group-sm">
          <a class="btn btn-outline-secondary" href="/asset-detail?id=${row.id}" title="Open">
            <i class="fa-solid fa-eye"></i></a>
          ${canEdit ? `<button class="btn btn-outline-primary" data-action="edit" data-id="${row.id}" title="Edit"><i class="fa-solid fa-pen"></i></button>` : ''}
          ${canDelete ? `<button class="btn btn-outline-danger" data-action="delete" data-id="${row.id}" title="Delete"><i class="fa-solid fa-trash"></i></button>` : ''}
        </div>`,
    },
  ],
});
 
filters.addEventListener('submit', (event) => {
  event.preventDefault();
  table.ajax.reload();
});
 
document.querySelector('[data-action="create-asset"]')?.addEventListener('click', async () => {
  await openModal({
    title: 'New asset',
    body: assetForm(),
    confirmLabel: 'Create',
    size: 'modal-lg',
    onConfirm: async (root) => {
      const payload = readAssetForm(root);
      if (!payload) return false;
      try {
        await api.post('/assets', payload);
        toastSuccess('Asset created');
        table.ajax.reload();
        return true;
      } catch (error) {
        toastError(error.message);
        return false;
      }
    },
  });
});
 
document.querySelector('[data-role="assets-table"]').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = Number(button.dataset.id);
 
  if (button.dataset.action === 'edit') {
    const asset = await withLoading(() => api.get(`/assets/${id}`));
    await openModal({
      title: `Edit ${asset.hostname}`,
      body: assetForm(asset),
      confirmLabel: 'Save',
      size: 'modal-lg',
      onConfirm: async (root) => {
        const payload = readAssetForm(root);
        if (!payload) return false;
        try {
          await api.put(`/assets/${id}`, payload);
          toastSuccess('Asset updated');
          table.ajax.reload(null, false);
          return true;
        } catch (error) {
          toastError(error.message);
          return false;
        }
      },
    });
    return;
  }
 
  if (button.dataset.action === 'delete') {
    const confirmed = await confirmDialog({
      message: 'Deleting this asset also removes its scans and findings. Continue?',
    });
    if (!confirmed) return;
    try {
      await withLoading(() => api.delete(`/assets/${id}`));
      toastSuccess('Asset deleted');
      table.ajax.reload(null, false);
    } catch (error) {
      toastError(error.message);
    }
  }
});