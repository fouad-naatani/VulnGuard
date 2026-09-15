/**
 * Login page controller.
 * @module pages/login
 */
 
import { login } from '/services/auth.js';
import { getAccessToken } from '/services/api.js';
import { applyTheme } from '/services/state.js';
import { toastError, toastInfo } from '/components/toast.js';
import { isEmail, setFieldValidity } from '/utils/validators.js';
 
const form = document.querySelector('[data-role="login-form"]');
const errorBox = document.querySelector('[data-role="login-error"]');
const submit = document.querySelector('[data-role="login-submit"]');
const spinner = document.querySelector('[data-role="login-spinner"]');
const label = document.querySelector('[data-role="login-label"]');
const successBox = document.querySelector('[data-role="login-success"]');
 
applyTheme();
 
// An already authenticated visitor goes straight to the dashboard.
if (getAccessToken()) {
  // Do not blindly trust a stale token: verify the session before redirecting.
  // requireAuth will clear an invalid/expired token and send the user to /login.
  window.location.replace('/dashboard');
}
 
/**
 * Toggle the submit button loading state.
 * @param {boolean} loading Whether a request is in flight.
 */
function setLoading(loading) {
  submit.disabled = loading;
  spinner.classList.toggle('d-none', !loading);
  label.textContent = loading ? 'Signing in…' : 'Sign in';
}
 
/**
 * Display an inline error message.
 * @param {string} message Error text.
 */
function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove('d-none');
}
 
document.querySelector('[data-action="toggle-password"]').addEventListener('click', (event) => {
  const input = document.querySelector('#password');
  const visible = input.type === 'text';
  input.type = visible ? 'password' : 'text';
  event.currentTarget.querySelector('i').className = visible
    ? 'fa-solid fa-eye'
    : 'fa-solid fa-eye-slash';
});
 
document.querySelector('[data-action="forgot-password"]').addEventListener('click', (event) => {
  event.preventDefault();
  toastInfo('Password resets are performed by an administrator from the Users page.');
});
 
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.classList.add('d-none');
 
  const email = form.email;
  const password = form.password;
  const emailValid = isEmail(email.value);
  const passwordValid = password.value.length > 0;
  setFieldValidity(email, emailValid, 'Enter a valid email address');
  setFieldValidity(password, passwordValid, 'Password is required');
  if (!emailValid || !passwordValid) return;
 
  setLoading(true);
  try {
    await login(email.value.trim(), password.value, form.remember?.checked ?? false);

    // The login endpoint has returned a token and the user profile.
    // Redirect immediately; the dashboard will perform the final session guard.
    form.classList.add('d-none');
    successBox.classList.remove('d-none');
    window.location.replace('/dashboard');
  } catch (error) {
    setLoading(false);
    showError(error.message);
    toastError(error.message);
  }
});