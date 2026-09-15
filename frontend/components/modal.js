/**
 * Reusable Bootstrap modal helpers: form modals, confirmation dialogs and a
 * full page loading spinner.
 * @module components/modal
 */
 
import { escapeHtml } from '../utils/format.js';
 
let counter = 0;
 
/**
 * Open a modal and resolve when it is closed.
 *
 * @param {{title: string, body: string, confirmLabel?: string, cancelLabel?: string,
 *          size?: string, variant?: string, onConfirm?: function(HTMLElement): (boolean|Promise<boolean>)}} options
 * @returns {Promise<boolean>} Whether the modal was confirmed.
 */
export function openModal({
  title,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  size = '',
  variant = 'primary',
  onConfirm,
}) {
  const id = `vg-modal-${(counter += 1)}`;
  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <div class="modal fade" id="${id}" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog ${size} modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">${escapeHtml(title)}</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">${body}</div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">${escapeHtml(cancelLabel)}</button>
            <button type="button" class="btn btn-${variant}" data-role="confirm">${escapeHtml(confirmLabel)}</button>
          </div>
        </div>
      </div>
    </div>
  `;
  const element = wrapper.firstElementChild;
  document.body.appendChild(element);
 
  const instance = new bootstrap.Modal(element);
  instance.show();
 
  return new Promise((resolve) => {
    let confirmed = false;
    const confirmButton = element.querySelector('[data-role="confirm"]');
 
    confirmButton.addEventListener('click', async () => {
      if (onConfirm) {
        confirmButton.disabled = true;
        let ok = false;
        try {
          ok = await onConfirm(element);
        } finally {
          confirmButton.disabled = false;
        }
        if (!ok) return;
      }
      confirmed = true;
      instance.hide();
    });
 
    element.addEventListener('hidden.bs.modal', () => {
      element.remove();
      resolve(confirmed);
    });
  });
}
 
/**
 * Ask the user to confirm a destructive action.
 * @param {{title?: string, message: string, confirmLabel?: string, variant?: string}} options
 * @returns {Promise<boolean>} Whether the user confirmed.
 */
export function confirmDialog({
  title = 'Please confirm',
  message,
  confirmLabel = 'Delete',
  variant = 'danger',
}) {
  return openModal({
    title,
    body: `<p class="mb-0">${escapeHtml(message)}</p>`,
    confirmLabel,
    variant,
  });
}
 
/**
 * Toggle the global loading spinner.
 * @param {boolean} visible Whether the spinner should be shown.
 */
export function setLoading(visible) {
  let overlay = document.querySelector('.spinner-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'spinner-overlay';
    overlay.innerHTML =
      '<div class="spinner-border text-primary" style="width:3rem;height:3rem" role="status">' +
      '<span class="visually-hidden">Loading…</span></div>';
    document.body.appendChild(overlay);
  }
  overlay.classList.toggle('is-visible', visible);
}
 
/**
 * Run an async task while the global spinner is displayed.
 * @template T
 * @param {function(): Promise<T>} task Async task.
 * @returns {Promise<T>} The task result.
 */
export async function withLoading(task) {
  setLoading(true);
  try {
    return await task();
  } finally {
    setLoading(false);
  }
}