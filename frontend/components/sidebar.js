/**
 * Application shell: injects the sidebar and the header, wires the collapsible
 * navigation, the theme switch, the notification centre and the global search.
 * @module components/sidebar
 */
 
import { logout } from '../services/auth.js';
import {
  clearNotifications,
  getNotifications,
  getState,
  getUser,
  hasRole,
  markNotificationsRead,
  setState,
  subscribe,
  toggleTheme,
} from '../services/state.js';
import { escapeHtml, formatRelative, humanize, initials } from '../utils/format.js';
 
/**
 * Navigation entries with the roles allowed to see them.
 * @type {{id: string, label: string, icon: string, href: string, roles: string[]}[]}
 */
export const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'fa-gauge-high', href: '/dashboard', roles: ['admin', 'soc_analyst', 'pentester', 'viewer'] },
  { id: 'assets', label: 'Assets', icon: 'fa-server', href: '/assets', roles: ['admin', 'soc_analyst', 'pentester', 'viewer'] },
  { id: 'scans', label: 'Scans', icon: 'fa-radar', href: '/scans', roles: ['admin', 'soc_analyst', 'pentester'] },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'fa-bug', href: '/vulnerabilities', roles: ['admin', 'soc_analyst', 'pentester', 'viewer'] },
  { id: 'reports', label: 'Reports', icon: 'fa-file-lines', href: '/reports', roles: ['admin', 'soc_analyst', 'pentester'] },
  { id: 'users', label: 'Users', icon: 'fa-users', href: '/users', roles: ['admin'] },
  { id: 'settings', label: 'Settings', icon: 'fa-gear', href: '/settings', roles: ['admin', 'soc_analyst', 'pentester', 'viewer'] },
];
 
/**
 * Load an HTML partial from the layout directory.
 * @param {string} name File name inside `layout/`.
 * @returns {Promise<string>} The partial markup.
 */
async function loadPartial(name) {
  const response = await fetch(`/layout/${name}`, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Unable to load layout partial ${name}`);
  return response.text();
}
 
/**
 * Render the role filtered navigation.
 * @param {HTMLElement} container Navigation container.
 * @param {string} active Identifier of the active page.
 */
function renderNav(container, active) {
  container.innerHTML = NAV_ITEMS.filter((item) => hasRole(...item.roles))
    .map(
      (item) => `
        <a class="app-sidebar__link ${item.id === active ? 'is-active' : ''}" href="${item.href}">
          <i class="fa-solid ${item.icon}"></i>
          <span class="app-sidebar__label">${item.label}</span>
        </a>`,
    )
    .join('');
}
 
/**
 * Render the notification dropdown content.
 * @param {HTMLElement} root Header root element.
 */
function renderNotifications(root) {
  const list = root.querySelector('[data-role="notification-list"]');
  const dot = root.querySelector('[data-role="notification-dot"]');
  if (!list) return;
  const notifications = getNotifications();
  dot?.classList.toggle('d-none', !notifications.some((item) => !item.read));
  list.innerHTML = notifications.length
    ? notifications
        .map(
          (item) => `
            <div class="px-3 py-2 border-bottom">
              <div class="d-flex justify-content-between gap-2">
                <strong class="small">${escapeHtml(item.title)}</strong>
                <small class="text-muted">${formatRelative(item.createdAt)}</small>
              </div>
              <div class="small text-muted">${escapeHtml(item.message)}</div>
            </div>`,
        )
        .join('')
    : '<div class="empty-state py-4"><i class="fa-regular fa-bell-slash"></i>No notification</div>';
}
 
/**
 * Render the header user identity block.
 * @param {HTMLElement} root Header root element.
 */
function renderUser(root) {
  const user = getUser();
  root.querySelector('[data-role="user-initials"]').textContent = initials(user?.full_name);
  root.querySelector('[data-role="user-name"]').textContent = user?.full_name ?? '—';
  root.querySelector('[data-role="user-role"]').textContent = humanize(user?.role);
}
 
/**
 * Update the theme toggle icon.
 * @param {HTMLElement} root Header root element.
 */
function renderThemeIcon(root) {
  const icon = root.querySelector('[data-role="theme-icon"]');
  if (icon) icon.className = getState().theme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
}
 
/**
 * Build the application shell for a page.
 * @param {{active: string}} options Identifier of the active navigation entry.
 * @returns {Promise<void>} Resolves once the shell is rendered.
 */
export async function initLayout({ active }) {
  const sidebar = document.querySelector('[data-role="app-sidebar"]');
  const header = document.querySelector('[data-role="app-header"]');
  const [sidebarHtml, headerHtml] = await Promise.all([
    loadPartial('sidebar.html'),
    loadPartial('header.html'),
  ]);
  sidebar.innerHTML = sidebarHtml;
  header.innerHTML = headerHtml;
 
  renderNav(sidebar.querySelector('[data-role="sidebar-nav"]'), active);
  renderUser(header);
  renderNotifications(header);
  renderThemeIcon(header);
 
  if (getState().sidebarCollapsed) document.body.classList.add('sidebar-collapsed');
 
  // --- Interactions ------------------------------------------------------
  header.querySelector('[data-action="toggle-sidebar"]').addEventListener('click', () => {
    if (window.innerWidth < 992) {
      document.body.classList.toggle('sidebar-open');
      return;
    }
    const collapsed = document.body.classList.toggle('sidebar-collapsed');
    setState({ sidebarCollapsed: collapsed });
  });
 
  header.querySelector('[data-action="toggle-theme"]').addEventListener('click', () => {
    toggleTheme();
    renderThemeIcon(header);
    document.dispatchEvent(new CustomEvent('vg:theme-changed'));
  });
 
  header
    .querySelector('[data-role="notifications-button"]')
    .addEventListener('click', () => markNotificationsRead());
 
  header.querySelector('[data-action="clear-notifications"]').addEventListener('click', () => {
    clearNotifications();
    renderNotifications(header);
  });
 
  header.querySelector('[data-role="global-search"]').addEventListener('submit', (event) => {
    event.preventDefault();
    const query = new FormData(event.currentTarget).get('q');
    if (query) window.location.href = `/vulnerabilities?search=${encodeURIComponent(query)}`;
  });
 
  document.querySelectorAll('[data-action="logout"]').forEach((element) =>
    element.addEventListener('click', (event) => {
      event.preventDefault();
      logout();
    }),
  );
 
  subscribe(() => renderNotifications(header));
}