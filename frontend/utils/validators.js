/**
 * Client side validators mirroring the backend rules.
 * @module utils/validators
 */
 
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const HOSTNAME_RE = /^(?!-)[A-Za-z0-9-_.]{1,253}(?<!-)$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4}:){1,7}:|(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){1,6}(:[0-9a-fA-F]{1,4}){1,1})$/;
 
/**
 * @param {string} value Candidate email address.
 * @returns {boolean} Whether the value looks like an email address.
 */
export function isEmail(value) {
  return EMAIL_RE.test(String(value ?? '').trim());
}
 
/**
 * @param {string} value Candidate IPv4 or IPv6 address.
 * @returns {boolean} Whether the value is a valid IP address.
 */
export function isIpAddress(value) {
  const candidate = String(value ?? '').trim();
  return IPV4_RE.test(candidate) || IPV6_RE.test(candidate);
}
 
/**
 * @param {string} value Candidate hostname.
 * @returns {boolean} Whether the value is a valid hostname.
 */
export function isHostname(value) {
  return HOSTNAME_RE.test(String(value ?? '').trim());
}
 
/**
 * Validate a password against the platform policy: at least 10 characters
 * mixing three of lowercase, uppercase, digits and symbols.
 * @param {string} value Candidate password.
 * @returns {{valid: boolean, message: string}} Validation outcome.
 */
export function checkPassword(value) {
  const password = String(value ?? '');
  if (password.length < 10) {
    return { valid: false, message: 'Password must be at least 10 characters long' };
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password));
  if (classes.length < 3) {
    return {
      valid: false,
      message: 'Password must mix at least three of: lowercase, uppercase, digits, symbols',
    };
  }
  return { valid: true, message: '' };
}
 
/**
 * Apply Bootstrap validation state to a field.
 * @param {HTMLElement} field Input element.
 * @param {boolean} valid Whether the field content is valid.
 * @param {string} [message] Feedback message displayed when invalid.
 */
export function setFieldValidity(field, valid, message = '') {
  field.classList.toggle('is-invalid', !valid);
  field.classList.toggle('is-valid', valid);
  const feedback = field.parentElement?.querySelector('.invalid-feedback');
  if (feedback && message) feedback.textContent = message;
}
 
/**
 * Validate a whole form from a field/validator map.
 * @param {Object<string, {field: HTMLElement, test: function(string): boolean, message: string}>} rules
 * @returns {boolean} Whether every field passed validation.
 */
export function validateForm(rules) {
  let valid = true;
  Object.values(rules).forEach(({ field, test, message }) => {
    const fieldValid = test(field.value);
    setFieldValidity(field, fieldValid, message);
    if (!fieldValid) valid = false;
  });
  return valid;
}