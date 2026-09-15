/**
 * Toast notifications.
 * @module components/toast
 */
 
import { escapeHtml } from '../utils/format.js';
 
const ICONS = {
  success: 'fa-circle-check',
  error: 'fa-circle-exclamation',
  warning: 'fa-triangle-exclamation',
  info: 'fa-circle-info',
};
 
/**
 * Lazily create the stack container that holds the toasts.
 * @returns {HTMLElement} Stack element.
 */
function stack() {
  let element = document.querySelector('.toast-stack');
  if (!element) {
    element = document.createElement('div');
    element.className = 'toast-stack';
    document.body.appendChild(element);
  }
  return element;
}
 
/**
 * Display a toast.
 * @param {string} message Message body.
 * @param {'success'|'error'|'warning'|'info'} [level='info'] Toast level.
 * @param {number} [timeout=4500] Auto-dismiss delay in milliseconds.
 */
export function showToast(message, level = 'info', timeout = 4500) {
  const toast = document.createElement('div');
  toast.className = `vg-toast vg-toast--${level}`;
  toast.setAttribute('role', 'status');
  toast.innerHTML = `
    <i class="fa-solid ${ICONS[level] ?? ICONS.info}" style="color: var(--${
      level === 'error' ? 'danger' : level
    }, var(--primary));"></i>
    <div class="flex-grow-1">${escapeHtml(message)}</div>
    <button type="button" class="btn-close btn-close-white btn-sm" aria-label="Close"></button>
  `;
 
  const remove = () => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 180);
  };
  toast.querySelector('.btn-close').addEventListener('click', remove);
  stack().appendChild(toast);
  if (timeout) setTimeout(remove, timeout);
}
 
/** @param {string} message Success message. */
export const toastSuccess = (message) => showToast(message, 'success');
/** @param {string} message Error message. */
export const toastError = (message) => showToast(message, 'error');
/** @param {string} message Warning message. */
export const toastWarning = (message) => showToast(message, 'warning');
/** @param {string} message Informational message. */
export const toastInfo = (message) => showToast(message, 'info');