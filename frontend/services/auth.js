/**
 * Authentication service: login, logout, session bootstrap and page guards.
 * @module services/auth
 */
 
import { api, clearTokens, getAccessToken, request, setTokens } from './api.js';
import { applyTheme, clearState, getState, hasRole, setState } from './state.js';
 
/** Path of the login page relative to the pages directory. */
const LOGIN_PAGE = '/login';
 
/**
 * Authenticate a user and persist the session.
 * @param {string} email User email.
 * @param {string} password Plaintext password.
 * @param {boolean} [remember=false] Keep the session after the browser closes.
 * @returns {Promise<object>} The authenticated user profile.
 */
export async function login(email, password, remember = false) {
  const data = await request('/login', {
    method: 'POST',
    auth: false,
    body: { email, password, remember_me: remember },
  });
  setTokens({ access: data.access_token, refresh: data.refresh_token }, remember);
  setState({ user: data.user });
  return data.user;
}
 
/**
 * Log out: notify the backend (best effort) and clear the local session.
 * @returns {Promise<void>}
 */
export async function logout() {
  try {
    if (getAccessToken()) await api.post('/logout');
  } catch {
    // Logging out must always succeed locally, even when offline.
  }
  clearTokens();
  clearState();
  window.location.href = LOGIN_PAGE;
}
 
/**
 * Refresh the cached user profile from the backend.
 * @returns {Promise<?object>} The user profile, or null when unauthenticated.
 */
export async function loadCurrentUser() {
  try {
    const user = await api.get('/me');
    setState({ user });
    return user;
  } catch {
    return null;
  }
}
 
/** @returns {boolean} Whether a session token is present. */
export function isAuthenticated() {
  return Boolean(getAccessToken());
}
 
/**
 * Guard a page: redirect to the login page when unauthenticated, and to the
 * dashboard when the user lacks one of the required roles.
 * @param {{roles?: string[]}} [options] Roles allowed on the page.
 * @returns {Promise<?object>} The authenticated user profile.
 */
export async function requireAuth({ roles } = {}) {
  applyTheme();
  if (!isAuthenticated()) {
    window.location.replace(LOGIN_PAGE);
    return null;
  }
  const user = getState().user ?? (await loadCurrentUser());
  if (!user) {
    clearTokens();
    window.location.replace(LOGIN_PAGE);
    return null;
  }
  if (roles?.length && !hasRole(...roles)) {
    window.location.replace('/dashboard');
    return null;
  }
  return user;
}
 
// A 401 raised anywhere in the app ends the session immediately.
document.addEventListener('vg:unauthorized', () => {
  if (window.location.pathname !== LOGIN_PAGE) {
    clearState();
    window.location.replace(LOGIN_PAGE);
  }
});