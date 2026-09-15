/**
 * Polling service used to refresh long running resources such as scans.
 * @module services/polling
 */
 
/** Default interval between two polls, in milliseconds. */
export const DEFAULT_INTERVAL = 5000;
 
/**
 * Repeatedly invoke an async task until it reports completion.
 *
 * @param {function(): Promise<*>} task Async function executed on each tick.
 * @param {{interval?: number, immediate?: boolean, until?: function(*): boolean,
 *          onError?: function(Error): void}} [options] Polling options.
 * @returns {{stop: function(): void, isRunning: function(): boolean}} Poll handle.
 */
export function startPolling(task, options = {}) {
  const {
    interval = DEFAULT_INTERVAL,
    immediate = true,
    until = () => false,
    onError = () => {},
  } = options;
 
  let timer = null;
  let running = true;
 
  const stop = () => {
    running = false;
    if (timer) clearTimeout(timer);
    timer = null;
  };
 
  const tick = async () => {
    if (!running) return;
    try {
      const result = await task();
      if (until(result)) {
        stop();
        return;
      }
    } catch (error) {
      onError(error);
    }
    if (running) timer = setTimeout(tick, interval);
  };
 
  if (immediate) {
    tick();
  } else {
    timer = setTimeout(tick, interval);
  }
 
  // Stop polling when the page is unloaded to avoid dangling timers.
  window.addEventListener('beforeunload', stop, { once: true });
 
  return { stop, isRunning: () => running };
}
 
/**
 * Poll only while the tab is visible, resuming automatically on focus.
 * @param {function(): Promise<*>} task Async function executed on each tick.
 * @param {object} [options] Same options as {@link startPolling}.
 * @returns {{stop: function(): void, isRunning: function(): boolean}} Poll handle.
 */
export function startVisiblePolling(task, options = {}) {
  let handle = startPolling(task, options);
  const onVisibility = () => {
    if (document.hidden) {
      handle.stop();
    } else if (!handle.isRunning()) {
      handle = startPolling(task, options);
    }
  };
  document.addEventListener('visibilitychange', onVisibility);
  return {
    stop: () => {
      document.removeEventListener('visibilitychange', onVisibility);
      handle.stop();
    },
    isRunning: () => handle.isRunning(),
  };
}