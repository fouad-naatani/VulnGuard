/**
 * Single HTTP wrapper around the FastAPI backend.
 *
 * Responsibilities:
 * - Resolve the FastAPI base URL
 * - Inject JWT access tokens
 * - Refresh expired access tokens
 * - Centralise HTTP error handling
 * - Build query strings
 *
 * @module services/api
 */

import { getState, setState } from './state.js';

const ACCESS_TOKEN_KEY = 'vg.accessToken';
const REFRESH_TOKEN_KEY = 'vg.refreshToken';

/**
 * Error carrying the HTTP status and backend payload.
 */
export class ApiError extends Error {
    /**
     * @param {string} message
     * @param {number} status
     * @param {*} [payload]
     */
    constructor(message, status, payload = null) {
        super(message);

        this.name = 'ApiError';
        this.status = status;
        this.payload = payload;
    }
}

/**
 * Resolve the API base URL.
 *
 * Development:
 *   Frontend: http://127.0.0.1:5500
 *   Backend:  http://127.0.0.1:8000
 *
 * Therefore:
 *   http://127.0.0.1:8000/api
 *
 * Production:
 *   Same-origin /api can be used behind a reverse proxy.
 *
 * @returns {string}
 */
export function getBaseUrl() {
    const state = getState();
    const configured = state?.apiUrl;

    /*
     * If a URL was explicitly configured in Settings,
     * use it only if it is a valid HTTP/HTTPS URL.
     */
    if (configured) {
        try {
            const parsed = new URL(configured);

            if (
                parsed.protocol === 'http:' ||
                parsed.protocol === 'https:'
            ) {
                const normalized = configured.replace(/\/+$/, '');

            // Settings may contain either the API root or the server root.
            // Always normalize it to the FastAPI API prefix.
            if (normalized === `${parsed.protocol}//${parsed.host}`) {
                return `${normalized}/api`;
            }
            return normalized.endsWith('/api') ? normalized : `${normalized}/api`;
            }
        } catch {
            console.warn(
                '[API] Invalid configured API URL:',
                configured
            );
        }
    }

    const {
        protocol,
        hostname,
        port,
    } = window.location;

    /*
     * Opening HTML directly from disk.
     */
    if (protocol === 'file:') {
        return 'http://127.0.0.1:8000/api';
    }

    /*
     * Frontend served by FastAPI itself.
     */
    if (port === '8000') {
        return `${protocol}//${hostname}:8000/api`;
    }

    /*
     * Local frontend development servers.
     *
     * 5500 = Live Server
     * 8080 = common frontend server
     * 3000 = common development server
     */
    if (
        port === '5500' ||
        port === '8080' ||
        port === '3000'
    ) {
        return `${protocol}//${hostname}:8000/api`;
    }

    /*
     * Production / reverse proxy.
     */
    return '/api';
}

/**
 * Override the API base URL.
 *
 * @param {?string} url
 */
export function setBaseUrl(url) {
    if (!url) {
        setState({ apiUrl: null });
        return;
    }

    try {
        const parsed = new URL(url);

        if (
            parsed.protocol !== 'http:' &&
            parsed.protocol !== 'https:'
        ) {
            throw new Error('API URL must use HTTP or HTTPS.');
        }

        setState({
            apiUrl: url.replace(/\/+$/, ''),
        });
    } catch (error) {
        console.error('[API] Invalid API URL:', error);
        throw new ApiError(
            'Invalid API URL. Use for example http://127.0.0.1:8000/api',
            0,
            { cause: String(error) }
        );
    }
}

/**
 * @returns {?string}
 */
export function getAccessToken() {
    return (
        localStorage.getItem(ACCESS_TOKEN_KEY) ??
        sessionStorage.getItem(ACCESS_TOKEN_KEY)
    );
}

/**
 * @returns {?string}
 */
export function getRefreshToken() {
    return (
        localStorage.getItem(REFRESH_TOKEN_KEY) ??
        sessionStorage.getItem(REFRESH_TOKEN_KEY)
    );
}

/**
 * Persist token pair.
 *
 * @param {{access?: string, refresh?: string}} tokens
 * @param {boolean} remember
 */
export function setTokens(
    { access, refresh },
    remember = false
) {
    const store = remember
        ? localStorage
        : sessionStorage;

    const other = remember
        ? sessionStorage
        : localStorage;

    other.removeItem(ACCESS_TOKEN_KEY);
    other.removeItem(REFRESH_TOKEN_KEY);

    if (access) {
        store.setItem(
            ACCESS_TOKEN_KEY,
            access
        );
    }

    if (refresh) {
        store.setItem(
            REFRESH_TOKEN_KEY,
            refresh
        );
    }
}

/**
 * Remove all stored tokens.
 */
export function clearTokens() {
    localStorage.removeItem(
        ACCESS_TOKEN_KEY
    );

    localStorage.removeItem(
        REFRESH_TOKEN_KEY
    );

    sessionStorage.removeItem(
        ACCESS_TOKEN_KEY
    );

    sessionStorage.removeItem(
        REFRESH_TOKEN_KEY
    );
}

/**
 * Build query string.
 *
 * @param {object} params
 * @returns {string}
 */
export function buildQuery(params = {}) {
    const search = new URLSearchParams();

    Object.entries(params).forEach(
        ([key, value]) => {
            if (
                value === undefined ||
                value === null ||
                value === ''
            ) {
                return;
            }

            search.append(
                key,
                String(value)
            );
        }
    );

    const query = search.toString();

    return query
        ? `?${query}`
        : '';
}

let refreshPromise = null;

/**
 * Refresh access token.
 *
 * @returns {Promise<?string>}
 */
async function refreshAccessToken() {
    const refresh = getRefreshToken();

    if (!refresh) {
        return null;
    }

    if (!refreshPromise) {
        refreshPromise = fetch(
            `${getBaseUrl()}/refresh`,
            {
                method: 'POST',
                headers: {
                    Accept:
                        'application/json',
                    'Content-Type':
                        'application/json',
                },
                body: JSON.stringify({
                    refresh_token: refresh,
                }),
            }
        )
            .then(async (response) => {
                if (!response.ok) {
                    return null;
                }

                const data =
                    await response.json();

                if (!data?.access_token) {
                    return null;
                }

                const remember =
                    Boolean(
                        localStorage.getItem(
                            REFRESH_TOKEN_KEY
                        )
                    );

                setTokens(
                    {
                        access:
                            data.access_token,
                        refresh,
                    },
                    remember
                );

                return data.access_token;
            })
            .catch((error) => {
                console.error(
                    '[API] Token refresh failed:',
                    error
                );

                return null;
            })
            .finally(() => {
                refreshPromise = null;
            });
    }

    return refreshPromise;
}

/**
 * Extract readable backend error.
 *
 * @param {*} payload
 * @param {number} status
 * @returns {string}
 */
function errorMessage(payload, status) {
    if (!payload) {
        return `Request failed with status ${status}`;
    }

    const detail = payload.detail;

    if (typeof detail === 'string') {
        return detail;
    }

    if (Array.isArray(detail)) {
        return detail
            .map((item) => {
                const location =
                    item.loc
                        ?.slice(1)
                        .join('.') ?? '';

                return `${location} ${item.msg}`.trim();
            })
            .join(', ');
    }

    if (
        typeof payload.message ===
        'string'
    ) {
        return payload.message;
    }

    return `Request failed with status ${status}`;
}

/**
 * Perform authenticated request.
 *
 * @param {string} path
 * @param {{
 *   method?: string,
 *   body?: *,
 *   params?: object,
 *   auth?: boolean,
 *   raw?: boolean
 * }} options
 *
 * @returns {Promise<*>}
 */
export async function request(
    path,
    options = {}
) {
    const {
        method = 'GET',
        body,
        params,
        auth = true,
        raw = false,
    } = options;

    const baseUrl =
        getBaseUrl();

    const normalizedPath =
        path.startsWith('/')
            ? path
            : `/${path}`;

    const url =
        `${baseUrl}${normalizedPath}` +
        `${buildQuery(params)}`;

    console.log(
        `[API] ${method} ${url}`
    );

    const send = async (token) => {
        return fetch(url, {
            method,

            headers: {
                Accept:
                    'application/json',

                ...(body !== undefined
                    ? {
                          'Content-Type':
                              'application/json',
                      }
                    : {}),

                ...(auth && token
                    ? {
                          Authorization:
                              `Bearer ${token}`,
                      }
                    : {}),
            },

            body:
                body !== undefined
                    ? JSON.stringify(body)
                    : undefined,
        });
    };

    let response;

    /*
     * Network-level error.
     *
     * This means the browser could not connect
     * to the FastAPI server.
     */
    try {
        response = await send(
            getAccessToken()
        );
    } catch (cause) {
        console.error(
            '[API] Network error:',
            cause
        );

        throw new ApiError(
            `Network error: the API is unreachable at ${baseUrl}`,
            0,
            {
                cause: String(cause),
                url,
            }
        );
    }

    /*
     * Access token expired.
     */
    if (
        response.status === 401 &&
        auth
    ) {
        const token =
            await refreshAccessToken();

        if (token) {
            try {
                response =
                    await send(token);
            } catch (cause) {
                throw new ApiError(
                    `Network error: the API is unreachable at ${baseUrl}`,
                    0,
                    {
                        cause:
                            String(cause),
                        url,
                    }
                );
            }
        }
    }

    /*
     * Raw response, used for downloads.
     */
    if (raw) {
        if (!response.ok) {
            const text =
                await response.text();

            throw new ApiError(
                `Download failed (${response.status})`,
                response.status,
                {
                    detail: text,
                }
            );
        }

        return response;
    }

    /*
     * Parse response safely.
     */
    const text =
        await response.text();

    let payload = null;

    if (text) {
        try {
            payload =
                JSON.parse(text);
        } catch {
            payload = {
                detail: text,
            };
        }
    }

    /*
     * HTTP error from FastAPI.
     */
    if (!response.ok) {
        if (response.status === 401) {
            clearTokens();

            document.dispatchEvent(
                new CustomEvent(
                    'vg:unauthorized'
                )
            );
        }

        throw new ApiError(
            errorMessage(
                payload,
                response.status
            ),
            response.status,
            payload
        );
    }

    return payload;
}

/**
 * API helper methods.
 */
export const api = {
    get: (path, params) =>
        request(path, {
            method: 'GET',
            params,
        }),

    post: (path, body) =>
        request(path, {
            method: 'POST',
            body,
        }),

    put: (path, body) =>
        request(path, {
            method: 'PUT',
            body,
        }),

    patch: (path, body) =>
        request(path, {
            method: 'PATCH',
            body,
        }),

    delete: (path) =>
        request(path, {
            method: 'DELETE',
        }),

    download: (path) =>
        request(path, {
            method: 'GET',
            raw: true,
        }),
};