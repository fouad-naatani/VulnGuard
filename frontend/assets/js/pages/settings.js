/**
 * Settings page controller: API URL, theme, password change and platform
 * configuration entries (JWT, SMTP, integrations).
 * @module pages/settings
 */
 
import { api, setBaseUrl } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { withLoading } from '/components/modal.js';
import { getState, hasRole, setTheme } from '/services/state.js';
import { escapeHtml, humanize } from '/utils/format.js';
import { checkPassword } from '/utils/validators.js';
 
await requireAuth();
await initLayout({ active: 'settings' });
 
const isAdmin = hasRole('admin');
const apiInput = document.querySelector('#setting-api-url');
const darkToggle = document.querySelector('#setting-dark-mode');
const groupsContainer = document.querySelector('[data-role="settings-groups"]');
 
apiInput.value = getState().apiUrl ?? '';
darkToggle.checked = getState().theme === 'dark';
 
document.querySelector('[data-action="save-api-url"]').addEventListener('click', () => {
  setBaseUrl(apiInput.value.trim());
  toastSuccess('API URL saved');
});
 
darkToggle.addEventListener('change', (event) => {
  setTheme(event.target.checked ? 'dark' : 'light');
  document.dispatchEvent(new CustomEvent('vg:theme-changed'));
});
 
/**
 * Render the platform settings grouped by category.
 * @param {object[]} settings Settings returned by the API.
 */
function renderSettings(settings) {
  const groups = settings.reduce((accumulator, setting) => {
    (accumulator[setting.category] ??= []).push(setting);
    return accumulator;
  }, {});
 
  groupsContainer.innerHTML = Object.entries(groups)
    .map(
      ([category, entries]) => `
        <h6 class="text-uppercase text-muted small mt-3 mb-2">${escapeHtml(humanize(category))}</h6>
        ${entries
          .map(
            (setting) => `
              <div class="mb-2">
                <label class="form-label small" for="setting-${escapeHtml(setting.key)}">
                  ${escapeHtml(humanize(setting.key))}
                </label>
                <input class="form-control" id="setting-${escapeHtml(setting.key)}"
                       data-key="${escapeHtml(setting.key)}"
                       data-category="${escapeHtml(setting.category)}"
                       data-secret="${setting.is_secret}"
                       type="${setting.is_secret ? 'password' : 'text'}"
                       value="${escapeHtml(setting.value ?? '')}" ${isAdmin ? '' : 'disabled'}>
              </div>`,
          )
          .join('')}`,
    )
    .join('');
}
 
try {
  renderSettings(await withLoading(() => api.get('/settings')));
} catch (error) {
  toastError(error.message);
}
 
if (isAdmin) {
  const saveButton = document.querySelector('[data-action="save-settings"]');
  saveButton.classList.remove('d-none');
  saveButton.addEventListener('click', async () => {
    const payload = [...groupsContainer.querySelectorAll('input[data-key]')].map((input) => ({
      key: input.dataset.key,
      value: input.value,
      category: input.dataset.category,
      is_secret: input.dataset.secret === 'true',
    }));
    try {
      renderSettings(await withLoading(() => api.put('/settings', payload)));
      toastSuccess('Settings saved');
    } catch (error) {
      toastError(error.message);
    }
  });
}
 
document.querySelector('[data-role="password-form"]').addEventListener('submit', async (event) => {
  event.preventDefault();
  const current = document.querySelector('#current-password');
  const next = document.querySelector('#new-password');
  const currentValid = current.value.length > 0;
  const check = checkPassword(next.value);
 
  current.classList.toggle('is-invalid', !currentValid);
  next.classList.toggle('is-invalid', !check.valid);
  if (check.message) next.parentElement.querySelector('.invalid-feedback').textContent = check.message;
  if (!currentValid || !check.valid) return;
 
  try {
    await withLoading(() =>
      api.post('/me/password', { current_password: current.value, new_password: next.value }),
    );
    toastSuccess('Password updated');
    event.target.reset();
    current.classList.remove('is-invalid', 'is-valid');
    next.classList.remove('is-invalid', 'is-valid');
  } catch (error) {
    toastError(error.message);
  }
});