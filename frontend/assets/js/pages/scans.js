/**
 * Scans page controller: create, start, stop and delete scan jobs.
 * @module pages/scans
 */

import { api } from '/services/api.js';
import { requireAuth } from '/services/auth.js';
import { initLayout } from '/components/sidebar.js';
import { createServerTable } from '/components/datatable.js';
import { progressBar, statusPill } from '/components/badge-criticite.js';
import {
    confirmDialog,
    openModal,
    withLoading,
} from '/components/modal.js';
import { toastError, toastSuccess } from '/components/toast.js';
import { startVisiblePolling } from '/services/polling.js';
import {
    escapeHtml,
    formatDate,
    humanize,
} from '/utils/format.js';
import {
    hasRole,
    pushNotification,
} from '/services/state.js';


/* -------------------------------------------------------------------------- */
/* Authentication / layout                                                    */
/* -------------------------------------------------------------------------- */

await requireAuth({
    roles: ['admin', 'soc_analyst', 'pentester'],
});

await initLayout({
    active: 'scans',
});


/* -------------------------------------------------------------------------- */
/* Filters                                                                    */
/* -------------------------------------------------------------------------- */

const filters = document.querySelector('[data-role="filters"]');

/**
 * @returns {object} Current filter values sent to the API.
 */
function filterParams() {
    if (!filters) {
        return {};
    }

    const data = new FormData(filters);

    return {
        search: data.get('search') || undefined,
        status: data.get('status') || undefined,
        scanner: data.get('scanner') || undefined,
    };
}


/* -------------------------------------------------------------------------- */
/* Permissions                                                                */
/* -------------------------------------------------------------------------- */

const canDelete = hasRole('admin');


/* -------------------------------------------------------------------------- */
/* Assets                                                                      */
/* -------------------------------------------------------------------------- */

const assets = await api
    .get('/assets', { page_size: 200 })
    .catch(() => ({ items: [] }));


/* -------------------------------------------------------------------------- */
/* Scanner definitions                                                        */
/* -------------------------------------------------------------------------- */

const SCANNERS = [
    {
        value: 'TRIVY',
        label: 'Trivy (containers & filesystems)',
        disabled: false,
    },
    {
        value: 'WAZUH',
        label: 'Wazuh (agent inventory)',
        disabled: false,
    },
    {
        value: 'NESSUS',
        label: 'Nessus (vulnerability scanner)',
        disabled: false,
    },
    {
        value: 'none',
        label: 'None',
        disabled: false,
    },
];


/**
 * Build scanner <option> elements.
 *
 * @param {string} selected Selected scanner.
 * @returns {string}
 */
function scannerOptions(selected = 'TRIVY') {
    return SCANNERS
        .map((scanner) => {
            const disabled = scanner.disabled ? ' disabled' : '';
            const selectedAttr =
                scanner.value === selected ? ' selected' : '';

            return `
                <option
                    value="${escapeHtml(scanner.value)}"
                    ${disabled}
                    ${selectedAttr}
                >
                    ${escapeHtml(scanner.label)}
                </option>
            `;
        })
        .join('');
}


/**
 * Build asset <option> elements.
 *
 * @returns {string}
 */
function assetOptions() {
    return [
        `<option value="">None</option>`,
        ...(assets.items || []).map((asset) => {
            const hostname = asset.hostname || 'Unknown host';
            const ip = asset.ip_address || '';

            return `
                <option value="${Number(asset.id)}">
                    ${escapeHtml(hostname)}
                    ${ip ? ` (${escapeHtml(ip)})` : ''}
                </option>
            `;
        }),
    ].join('');
}


/* -------------------------------------------------------------------------- */
/* Create scan modal                                                           */
/* -------------------------------------------------------------------------- */

function scanForm() {
    return `
        <form novalidate data-role="scan-form">

            <div class="mb-3">
                <label class="form-label" for="scan-name">
                    Name *
                </label>

                <input
                    class="form-control"
                    id="scan-name"
                    name="name"
                    required
                    placeholder="Nessus vulnerability scan"
                >

                <div class="invalid-feedback">
                    A scan name is required.
                </div>
            </div>


            <div class="mb-3">
                <label class="form-label" for="scan-scanner">
                    Scanner
                </label>

                <select
                    class="form-select"
                    id="scan-scanner"
                    name="scanner"
                    required
                >
                    ${scannerOptions('TRIVY')}
                </select>

                <div class="form-text">
                    Select the vulnerability scanner to use.
                </div>
            </div>


            <div class="mb-3">
                <label class="form-label" for="scan-target">
                    Target *
                </label>

                <input
                    class="form-control"
                    id="scan-target"
                    name="target"
                    required
                    placeholder="192.168.1.100"
                >

                <div class="invalid-feedback">
                    A target is required.
                </div>

                <div class="form-text">
                    For Nessus, enter the hostname or IP address to scan.
                </div>
            </div>


            <div class="mb-3">
                <label class="form-label" for="scan-asset">
                    Linked asset
                </label>

                <select
                    class="form-select"
                    id="scan-asset"
                    name="asset_id"
                >
                    ${assetOptions()}
                </select>
            </div>


            <div class="form-check">
                <input
                    class="form-check-input"
                    type="checkbox"
                    id="scan-start"
                    name="start"
                    checked
                >

                <label
                    class="form-check-label"
                    for="scan-start"
                >
                    Start immediately
                </label>
            </div>

        </form>
    `;
}


/* -------------------------------------------------------------------------- */
/* Scans table                                                                 */
/* -------------------------------------------------------------------------- */

const table = createServerTable({
    selector: '[data-role="scans-table"]',
    endpoint: '/scans',
    params: filterParams,
    searching: false,

    columns: [
        {
            data: 'name',

            render: (value, type, row) => `
                <a href="/scan-detail?id=${row.id}">
                    ${escapeHtml(value || '')}
                </a>
            `,
        },

        {
            data: 'scanner',
            orderable: false,

            render: (value) => {
                if (!value) {
                    return '-';
                }

                return `
                    <span class="tag-chip">
                        ${escapeHtml(humanize(value))}
                    </span>
                `;
            },
        },

        {
            data: 'target',
            orderable: false,

            render: (value) => `
                <span
                    class="text-truncate d-inline-block"
                    style="max-width:260px"
                    title="${escapeHtml(value || '')}"
                >
                    ${escapeHtml(value || '')}
                </span>
            `,
        },

        {
            data: 'status',
            orderable: false,

            render: (value) => statusPill(value),
        },

        {
            data: 'progress',
            orderable: false,

            render: (value, type, row) => `
                <div style="min-width:120px">
                    ${progressBar(value ?? 0, row.status)}
                </div>
            `,
        },

        {
            data: 'vulnerability_count',
            orderable: false,

            render: (value) => value ?? 0,
        },

        {
            data: 'started_at',
            orderable: false,

            render: (value) => formatDate(value),
        },

        {
            data: null,
            orderable: false,
            className: 'text-end',

            render: (value, type, row) => {
                const buttons = [];

                buttons.push(`
                    <a
                        class="btn btn-outline-secondary btn-sm"
                        href="/scan-detail?id=${row.id}"
                        title="Open"
                    >
                        <i class="fa-solid fa-eye"></i>
                    </a>
                `);

                if (row.status === 'pending') {
                    buttons.push(`
                        <button
                            class="btn btn-outline-success btn-sm"
                            data-action="start"
                            data-id="${row.id}"
                            title="Start"
                        >
                            <i class="fa-solid fa-play"></i>
                        </button>
                    `);
                }

                if (row.status === 'running') {
                    buttons.push(`
                        <button
                            class="btn btn-outline-warning btn-sm"
                            data-action="stop"
                            data-id="${row.id}"
                            title="Stop"
                        >
                            <i class="fa-solid fa-stop"></i>
                        </button>
                    `);
                }

                if (canDelete) {
                    buttons.push(`
                        <button
                            class="btn btn-outline-danger btn-sm"
                            data-action="delete"
                            data-id="${row.id}"
                            title="Delete"
                        >
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    `);
                }

                return `
                    <div class="btn-group btn-group-sm">
                        ${buttons.join('')}
                    </div>
                `;
            },
        },
    ],
});


/* -------------------------------------------------------------------------- */
/* Filter submit                                                               */
/* -------------------------------------------------------------------------- */

if (filters) {
    filters.addEventListener('submit', (event) => {
        event.preventDefault();

        table.ajax.reload(null, false);
    });
}


/* -------------------------------------------------------------------------- */
/* Create scan                                                                  */
/* -------------------------------------------------------------------------- */

const createScanButton =
    document.querySelector('[data-action="create-scan"]');

if (createScanButton) {
    createScanButton.addEventListener('click', async () => {

        await openModal({
            title: 'New scan',

            body: scanForm(),

            confirmLabel: 'Create scan',

            onConfirm: async (root) => {

                const form =
                    root.querySelector('[data-role="scan-form"]');

                if (!form) {
                    toastError('Scan form not found.');
                    return false;
                }

                const name = form.name.value.trim();
                const scanner = form.scanner.value;
                const target = form.target.value.trim();

                const assetId = form.asset_id.value
                    ? Number(form.asset_id.value)
                    : null;

                const startImmediately =
                    form.start.checked;


                /* ---------------------------------------------------------- */
                /* Validation                                                  */
                /* ---------------------------------------------------------- */

                const nameValid = name.length > 0;
                const targetValid = target.length > 0;

                form.name.classList.toggle(
                    'is-invalid',
                    !nameValid,
                );

                form.target.classList.toggle(
                    'is-invalid',
                    !targetValid,
                );

                if (!nameValid || !targetValid) {
                    return false;
                }


                /* ---------------------------------------------------------- */
                /* Validate scanner                                            */
                /* ---------------------------------------------------------- */

                const scannerExists = SCANNERS.some(
                    (item) =>
                        item.value === scanner &&
                        !item.disabled,
                );

                if (!scannerExists) {
                    toastError('Invalid scanner selected.');
                    return false;
                }


                /* ---------------------------------------------------------- */
                /* Nessus                                                       */
                /* ---------------------------------------------------------- */

                if (scanner === 'NESSUS') {
                    console.log(
                        '[VulnGuard] Creating Nessus scan:',
                        {
                            name,
                            target,
                            asset_id: assetId,
                            start_immediately: startImmediately,
                        },
                    );
                }


                /* ---------------------------------------------------------- */
                /* Create backend scan                                          */
                /* ---------------------------------------------------------- */

                try {

                    const payload = {
                        name,
                        scanner,
                        target,
                        asset_id: assetId,
                        start_immediately: startImmediately,
                    };

                    console.log(
                        '[VulnGuard] POST /scans',
                        payload,
                    );

                    await api.post('/scans', payload);

                    toastSuccess(
                        scanner === 'NESSUS'
                            ? 'Nessus scan created'
                            : 'Scan created',
                    );

                    pushNotification({
                        title: 'Scan created',
                        message: `${name} (${humanize(scanner)})`,
                    });

                    table.ajax.reload(null, false);

                    return true;

                } catch (error) {

                    console.error(
                        '[VulnGuard] Scan creation failed:',
                        error,
                    );

                    toastError(
                        error?.message ||
                        'Failed to create scan.',
                    );

                    return false;
                }
            },
        });
    });
}


/* -------------------------------------------------------------------------- */
/* Scan actions                                                                */
/* -------------------------------------------------------------------------- */

const scansTable =
    document.querySelector('[data-role="scans-table"]');

if (scansTable) {

    scansTable.addEventListener('click', async (event) => {

        const button =
            event.target.closest('button[data-action]');

        if (!button) {
            return;
        }

        const id = Number(button.dataset.id);
        const action = button.dataset.action;


        try {

            if (action === 'start') {

                await withLoading(
                    () => api.post(`/scans/${id}/start`),
                );

                toastSuccess('Scan started');
            }


            else if (action === 'stop') {

                await withLoading(
                    () => api.post(`/scans/${id}/stop`),
                );

                toastSuccess('Scan stopped');
            }


            else if (action === 'delete') {

                const confirmed =
                    await confirmDialog({
                        message:
                            'Delete this scan and its findings?',
                    });

                if (!confirmed) {
                    return;
                }

                await withLoading(
                    () => api.delete(`/scans/${id}`),
                );

                toastSuccess('Scan deleted');
            }


            table.ajax.reload(null, false);

        } catch (error) {

            toastError(
                error?.message ||
                'Scan operation failed.',
            );
        }
    });
}


/* -------------------------------------------------------------------------- */
/* Live refresh                                                                */
/* -------------------------------------------------------------------------- */

startVisiblePolling(
    async () => {

        const running =
            await api.get('/scans', {
                status: 'running',
                page_size: 1,
            });

        const pending =
            await api.get('/scans', {
                status: 'pending',
                page_size: 1,
            });

        const activeCount =
            (running.total || 0) +
            (pending.total || 0);

        if (activeCount > 0) {
            table.ajax.reload(null, false);
        }

        return activeCount;
    },

    {
        interval: 5000,
        immediate: false,
        onError: () => {},
    },
);