/**
 * Severity and status badges ("criticité" badges).
 * @module components/badge-criticite
 */
 
import { escapeHtml, formatCvss, humanize } from '../utils/format.js';
 
/**
 * Render a severity badge.
 * @param {string} severity Severity identifier (critical, high, ...).
 * @returns {string} HTML markup.
 */
export function severityBadge(severity) {
  const value = String(severity ?? 'info').toLowerCase();
  return `<span class="severity-badge severity-badge--${escapeHtml(value)}">${escapeHtml(value)}</span>`;
}
 
/**
 * Render a CVSS score badge coloured by its severity bucket.
 * @param {?number} score CVSS base score.
 * @returns {string} HTML markup.
 */
export function cvssBadge(score) {
  const value = Number(score ?? 0);
  let level = 'info';
  if (value >= 9) level = 'critical';
  else if (value >= 7) level = 'high';
  else if (value >= 4) level = 'medium';
  else if (value > 0) level = 'low';
  return `<span class="severity-badge severity-badge--${level}">${formatCvss(value)}</span>`;
}
 
/**
 * Render a status pill (scan status, agent status, report status...).
 * @param {string} status Status identifier.
 * @returns {string} HTML markup.
 */
export function statusPill(status) {
  const value = String(status ?? 'unknown').toLowerCase();
  return `<span class="status-pill status-pill--${escapeHtml(value)}">
    <span class="status-pill__dot"></span>${escapeHtml(humanize(value))}</span>`;
}
 
/**
 * Render a list of tags as chips.
 * @param {string[]} [tags] Tag list.
 * @returns {string} HTML markup.
 */
export function tagChips(tags = []) {
  if (!tags.length) return '<span class="text-muted">—</span>';
  return tags.map((tag) => `<span class="tag-chip">${escapeHtml(tag)}</span>`).join('');
}
 
/**
 * Render a progress bar coloured by scan status.
 * @param {number} progress Percentage between 0 and 100.
 * @param {string} [status] Scan status.
 * @returns {string} HTML markup.
 */
export function progressBar(progress, status = 'running') {
  const colors = {
    completed: 'bg-success',
    failed: 'bg-danger',
    cancelled: 'bg-secondary',
    running: 'bg-primary',
    pending: 'bg-warning',
  };
  const value = Math.max(0, Math.min(100, Number(progress ?? 0)));
  return `<div class="progress" role="progressbar" aria-valuenow="${value}" aria-valuemin="0" aria-valuemax="100">
      <div class="progress-bar ${colors[status] ?? 'bg-primary'}" style="width:${value}%"></div>
    </div>`;
}