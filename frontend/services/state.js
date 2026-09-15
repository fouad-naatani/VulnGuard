/**
 * Client side application state: current user, role, theme and notifications.
 * State is persisted in localStorage so it survives page navigation, and
 * subscribers are notified on every change.
 * @module services/state
 */
 
const STORAGE_KEY = 'vg.state';
 
/** @typedef {{id: string, title: string, message: string, level: string, createdAt: string, read: boolean}} Notification */
 
const defaultState = {
  user: null,
  theme: 'dark',
  sidebarCollapsed: false,
  notifications: /** @type {Notification[]} */ ([]),
  apiUrl: null,
};
 
/** @type {Set<function(object): void>} */
const listeners = new Set();
 
/**
 * Read the persisted state, falling back to defaults.
 * @returns {object} Current state.
 */
function read() {
  try {
    return { ...defaultState, ...JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') };
  } catch {
    return { ...defaultState };
  }
}
 
let state = read();
 
/** @returns {object} A shallow copy of the current state. */
export function getState() {
  return { ...state };
}
 
/**
 * Merge a partial state, persist it and notify subscribers.
 * @param {object} patch Partial state.
 */
export function setState(patch) {
  state = { ...state, ...patch };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  listeners.forEach((listener) => listener(getState()));
}
 
/**
 * Subscribe to state changes.
 * @param {function(object): void} listener Called on every change.
 * @returns {function(): void} Unsubscribe function.
 */
export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
 
/** Reset the state to its defaults (used on logout). */
export function clearState() {
  state = { ...defaultState, theme: state.theme, apiUrl: state.apiUrl };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  listeners.forEach((listener) => listener(getState()));
}
 
/** @returns {?object} The authenticated user profile. */
export function getUser() {
  return state.user;
}
 
/** @returns {string} The role of the authenticated user, or `viewer`. */
export function getRole() {
  return state.user?.role ?? 'viewer';
}
 
/**
 * Check whether the current user owns one of the given roles.
 * @param {...string} roles Accepted roles.
 * @returns {boolean} Whether access is granted.
 */
export function hasRole(...roles) {
  return roles.includes(getRole());
}
 
/** @returns {string} The active theme (`dark` or `light`). */
export function getTheme() {
  return state.theme;
}
 
/**
 * Persist and apply a theme.
 * @param {string} theme `dark` or `light`.
 */
export function setTheme(theme) {
  setState({ theme });
  applyTheme();
}
 
/** Apply the persisted theme to the document element. */
export function applyTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
}
 
/** Toggle between the dark and light themes. */
export function toggleTheme() {
  setTheme(state.theme === 'dark' ? 'light' : 'dark');
}
 
/**
 * Add a notification to the header notification centre.
 * @param {{title: string, message: string, level?: string}} notification Notification content.
 */
export function pushNotification({ title, message, level = 'info' }) {
  const notifications = [
    {
      id: crypto.randomUUID(),
      title,
      message,
      level,
      createdAt: new Date().toISOString(),
      read: false,
    },
    ...state.notifications,
  ].slice(0, 30);
  setState({ notifications });
}
 
/** @returns {Notification[]} Stored notifications, newest first. */
export function getNotifications() {
  return state.notifications;
}
 
/** Mark every notification as read. */
export function markNotificationsRead() {
  setState({ notifications: state.notifications.map((item) => ({ ...item, read: true })) });
}
 
/** Remove every notification. */
export function clearNotifications() {
  setState({ notifications: [] });
}