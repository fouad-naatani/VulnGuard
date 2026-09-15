/**
 * Users page controller (administrators only).
 * @module pages/users
 */
 
import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { statusPill } from '/components/badge-criticite.js';
import { confirmDialog, openModal, withLoading } from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { escapeHtml, formatDate, humanize } from '/utils/format.js';
import { checkPassword, isEmail } from '/utils/validators.js';
 
const ROLES = ['admin', 'soc_analyst', 'pentester', 'viewer'];
 
const currentUser = await requireAuth({ roles: ['admin'] });
await initLayout({ active: 'users' });
 
/**
 * Build the user form markup.
 * @param {object} [user] Existing user when editing.
 * @returns {string} Form markup.
 */
function userForm(user = {}) {
  const editing = Boolean(user.id);
  return `
    <form novalidate data-role="user-form">
      <div class="row g-3">
        <div class="col-12 col-md-6">
          <label class="form-label" for="user-name">Full name *</label>
          <input class="form-control" id="user-name" name="full_name" required value="${escapeHtml(user.full_name ?? '')}">
          <div class="invalid-feedback">A name is required</div>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="user-email">Email *</label>
          <input type="email" class="form-control" id="user-email" name="email" required value="${escapeHtml(user.email ?? '')}">
          <div class="invalid-feedback">Enter a valid email address</div>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="user-role">Role</label>
          <select class="form-select" id="user-role" name="role">
            ${ROLES.map((role) => `<option value="${role}" ${user.role === role ? 'selected' : ''}>${humanize(role)}</option>`).join('')}
          </select>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label" for="user-password">${editing ? 'New password (optional)' : 'Password *'}</label>
          <input type="password" class="form-control" id="user-password" name="password"
                 autocomplete="new-password" ${editing ? '' : 'required'}>
          <div class="invalid-feedback" data-role="password-feedback">Password policy not met</div>
        </div>
        <div class="col-12">
          <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" role="switch" id="user-active" name="is_active"
                   ${user.is_active === false ? '' : 'checked'}>
            <label class="form-check-label" for="user-active">Account active</label>
          </div>
        </div>
      </div>
    </form>`;
}
 
/**
 * Validate and read the user form.
 * @param {HTMLElement} root Modal root.
 * @param {boolean} editing Whether an existing user is being updated.
 * @returns {?object} Payload, or null when invalid.
 */
function readUserForm(root, editing) {
  const form = root.querySelector('[data-role="user-form"]');
  const nameValid = form.full_name.value.trim().length > 0;
  const emailValid = isEmail(form.email.value);
  const password = form.password.value;
  const passwordCheck = password ? checkPassword(password) : { valid: editing, message: '' };
 
  form.full_name.classList.toggle('is-invalid', !nameValid);
  form.email.classList.toggle('is-invalid', !emailValid);
  form.password.classList.toggle('is-invalid', !passwordCheck.valid);
  if (passwordCheck.message) {
    root.querySelector('[data-role="password-feedback"]').textContent = passwordCheck.message;
  }
  if (!nameValid || !emailValid || !passwordCheck.valid) return null;
 
  const payload = {
    full_name: form.full_name.value.trim(),
    email: form.email.value.trim().toLowerCase(),
    role: form.role.value,
    is_active: form.is_active.checked,
  };
  if (password) payload.password = password;
  return payload;
}
 
const table = createServerTable({
  selector: '[data-role="users-table"]',
  endpoint: '/users',
  searching: true,
  columns: [
    { data: 'full_name', orderable: false, render: (value) => escapeHtml(value) },
    { data: 'email', orderable: false, render: (value) => escapeHtml(value) },
    { data: 'role', orderable: false, render: (value) => `<span class="tag-chip">${escapeHtml(humanize(value))}</span>` },
    {
      data: 'is_active',
      orderable: false,
      render: (value) => statusPill(value ? 'online' : 'offline').replace('Online', 'Active').replace('Offline', 'Disabled'),
    },
    { data: 'last_login_at', orderable: false, render: (value) => formatDate(value) },
    {
      data: null,
      orderable: false,
      className: 'text-end',
      render: (value, type, row) => `
        <div class="btn-group btn-group-sm">
          <button class="btn btn-outline-primary" data-action="edit" data-id="${row.id}" title="Edit">
            <i class="fa-solid fa-pen"></i></button>
          <button class="btn btn-outline-warning" data-action="toggle" data-id="${row.id}"
                  data-active="${row.is_active}" title="${row.is_active ? 'Deactivate' : 'Activate'}"
                  ${row.id === currentUser.id ? 'disabled' : ''}>
            <i class="fa-solid ${row.is_active ? 'fa-user-slash' : 'fa-user-check'}"></i></button>
          <button class="btn btn-outline-danger" data-action="delete" data-id="${row.id}"
                  ${row.id === currentUser.id ? 'disabled' : ''} title="Delete">
            <i class="fa-solid fa-trash"></i></button>
        </div>`,
    },
  ],
});
 
document.querySelector('[data-action="create-user"]').addEventListener('click', async () => {
  await openModal({
    title: 'New user',
    body: userForm(),
    confirmLabel: 'Create',
    size: 'modal-lg',
    onConfirm: async (root) => {
      const payload = readUserForm(root, false);
      if (!payload) return false;
      try {
        await api.post('/users', payload);
        toastSuccess('User created');
        table.ajax.reload(null, false);
        return true;
      } catch (error) {
        toastError(error.message);
        return false;
      }
    },
  });
});
 
document.querySelector('[data-role="users-table"]').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = Number(button.dataset.id);
  const action = button.dataset.action;
 
  if (action === 'edit') {
    const user = await withLoading(() => api.get(`/users/${id}`));
    await openModal({
      title: `Edit ${user.full_name}`,
      body: userForm(user),
      confirmLabel: 'Save',
      size: 'modal-lg',
      onConfirm: async (root) => {
        const payload = readUserForm(root, true);
        if (!payload) return false;
        try {
          await api.put(`/users/${id}`, payload);
          toastSuccess('User updated');
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
 
  try {
    if (action === 'toggle') {
      const active = button.dataset.active === 'true';
      await withLoading(() => api.put(`/users/${id}`, { is_active: !active }));
      toastSuccess(active ? 'User deactivated' : 'User activated');
    } else if (action === 'delete') {
      const confirmed = await confirmDialog({ message: 'Permanently delete this user account?' });
      if (!confirmed) return;
      await withLoading(() => api.delete(`/users/${id}`));
      toastSuccess('User deleted');
    }
    table.ajax.reload(null, false);
  } catch (error) {
    toastError(error.message);
  }
});