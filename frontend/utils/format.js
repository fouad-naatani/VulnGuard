/**
 * Formatting helpers shared by every page.
 * @module utils/format
 */
 
/** Severity colour tokens, mirroring the CSS custom properties. */
export const SEVERITY_COLORS = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#F59E0B',
  low: '#10B981',
  info: '#3B82F6',
};
 
/** Ordering used when sorting findings from most to least urgent. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
 
/**
 * Format an ISO timestamp as a readable local date and time.
 * @param {?string} value ISO 8601 timestamp.
 * @param {boolean} [withTime=true] Include hours and minutes.
 * @returns {string} Formatted date, or an em dash when empty.
 */
export function formatDate(value, withTime = true) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const options = { year: 'numeric', month: 'short', day: '2-digit' };
  if (withTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
  }
  return date.toLocaleString(undefined, options);
}
 
/**
 * Format a timestamp as a relative age, e.g. "3 h ago".
 * @param {?string} value ISO 8601 timestamp.
 * @returns {string} Relative description.
 */
export function formatRelative(value) {
  if (!value) return '—';
  const diff = Date.now() - new Date(value).getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} d ago`;
}
 
/**
 * Format a duration expressed in seconds as `1h 02m 03s`.
 * @param {?number} seconds Duration in seconds.
 * @returns {string} Human readable duration.
 */
export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const total = Math.max(0, Math.round(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  if (minutes) return `${minutes}m ${String(secs).padStart(2, '0')}s`;
  return `${secs}s`;
}
 
/**
 * Format a CVSS base score with one decimal.
 * @param {?number} score CVSS score.
 * @returns {string} Formatted score.
 */
export function formatCvss(score) {
  if (score === null || score === undefined) return '—';
  return Number(score).toFixed(1);
}
 
/**
 * Format an EPSS probability as a percentage.
 * @param {?number} score EPSS probability between 0 and 1.
 * @returns {string} Formatted percentage.
 */
export function formatEpss(score) {
  if (score === null || score === undefined) return '—';
  return `${(Number(score) * 100).toFixed(1)} %`;
}
 
/**
 * Format a byte count using binary multiples.
 * @param {number} bytes Size in bytes.
 * @returns {string} Formatted size.
 */
export function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
 
/**
 * Return the colour associated with a severity level.
 * @param {string} severity Severity identifier.
 * @returns {string} Hexadecimal colour.
 */
export function severityColor(severity) {
  return SEVERITY_COLORS[String(severity).toLowerCase()] ?? SEVERITY_COLORS.info;
}
 
/**
 * Convert a snake_case identifier into a capitalised label.
 * @param {?string} value Raw identifier.
 * @returns {string} Human readable label.
 */
export function humanize(value) {
  if (!value) return '—';
  return String(value)
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
 
/**
 * Escape a string for safe interpolation into HTML.
 * @param {*} value Untrusted value.
 * @returns {string} Escaped text.
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
 
/**
 * Truncate a string, appending an ellipsis when it was shortened.
 * @param {?string} value Input text.
 * @param {number} [length=120] Maximum length.
 * @returns {string} Possibly truncated text.
 */
export function truncate(value, length = 120) {
  if (!value) return '';
  return value.length > length ? `${value.slice(0, length)}…` : value;
}
 
/**
 * Build the initials shown in the header avatar.
 * @param {?string} fullName User full name.
 * @returns {string} Up to two upper case initials.
 */
export function initials(fullName) {
  if (!fullName) return '?';
  return fullName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join('');
}