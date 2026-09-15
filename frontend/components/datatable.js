/**
 * DataTables wrappers.
 *
 * createServerTable:
 *   DataTables + FastAPI server-side pagination.
 *
 * createClientTable:
 *   DataTables using an in-memory dataset.
 *
 * @module components/datatable
 */

import { api } from '../services/api.js';
import { toastError } from './toast.js';


/**
 * Shared DataTables configuration.
 */
const BASE_OPTIONS = {
    responsive: true,

    autoWidth: false,

    lengthMenu: [
        10,
        20,
        50,
        100,
    ],

    language: {
        search: '',

        searchPlaceholder:
            'Search…',

        lengthMenu:
            '_MENU_ per page',

        info:
            '_START_–_END_ of _TOTAL_',

        infoEmpty:
            'No entry',

        zeroRecords:
            'No matching record found',

        emptyTable:
            'No data available',

        paginate: {
            previous:
                '<i class="fa-solid fa-chevron-left"></i>',

            next:
                '<i class="fa-solid fa-chevron-right"></i>',
        },
    },
};


/**
 * Create a DataTable backed by FastAPI.
 *
 * Expected backend response:
 *
 * {
 *     "items": [...],
 *     "total": 123
 * }
 *
 * @param {{
 *   selector: string,
 *   endpoint: string,
 *   columns: object[],
 *   order?: Array,
 *   sortFields?: Object,
 *   params?: function(): object,
 *   pageLength?: number,
 *   searching?: boolean
 * }} config
 *
 * @returns {object}
 */
export function createServerTable(
    config
) {
    const {
        selector,
        endpoint,
        columns,

        order = [],

        sortFields = {},

        params = () => ({}),

        pageLength = 20,

        searching = true,

    } = config;


    const table =
        new DataTable(
            selector,
            {
                ...BASE_OPTIONS,

                serverSide: true,

                processing: true,

                searching,

                pageLength,

                order,

                columns,

                ajax:
                    async (
                        data,
                        callback
                    ) => {

                        /*
                         * DataTables:
                         *
                         * start = first row
                         * length = rows per page
                         *
                         * Convert to:
                         *
                         * page = 1, 2, 3...
                         */
                        const page =
                            Math.floor(
                                data.start /
                                data.length
                            ) + 1;


                        const sortColumn =
                            data.order?.[0];


                        const query = {
                            page,

                            page_size:
                                data.length,

                            search:
                                data.search
                                    ?.value ||
                                undefined,

                            ...params(),
                        };


                        /*
                         * Sorting.
                         */
                        if (
                            sortColumn &&
                            sortFields[
                                sortColumn.column
                            ]
                        ) {
                            query.sort_by =
                                sortFields[
                                    sortColumn.column
                                ];

                            query.sort_dir =
                                sortColumn.dir;
                        }


                        console.group(
                            '[DataTable]'
                        );

                        console.log(
                            'Endpoint:',
                            endpoint
                        );

                        console.log(
                            'Query:',
                            query
                        );

                        console.groupEnd();


                        try {

                            const response =
                                await api.get(
                                    endpoint,
                                    query
                                );


                            console.log(
                                '[DataTable] Response:',
                                response
                            );


                            /*
                             * FastAPI response:
                             *
                             * {
                             *   items: [],
                             *   total: 5
                             * }
                             */
                            const items =
                                Array.isArray(
                                    response?.items
                                )
                                    ? response.items
                                    : [];


                            const total =
                                Number(
                                    response?.total ??
                                    0
                                );


                            callback({
                                draw:
                                    data.draw,

                                recordsTotal:
                                    total,

                                recordsFiltered:
                                    total,

                                data:
                                    items,
                            });


                        } catch (error) {

                            console.error(
                                '[DataTable] API error:',
                                error
                            );


                            console.error(
                                '[DataTable] Status:',
                                error?.status
                            );


                            console.error(
                                '[DataTable] Payload:',
                                error?.payload
                            );


                            /*
                             * Display backend error.
                             */
                            toastError(
                                error?.message ||
                                'Unable to load data.'
                            );


                            /*
                             * Give DataTables
                             * an empty result so
                             * it doesn't crash.
                             */
                            callback({
                                draw:
                                    data.draw,

                                recordsTotal:
                                    0,

                                recordsFiltered:
                                    0,

                                data: [],
                            });
                        }
                    },
            }
        );


    return table;
}


/**
 * Create a client-side DataTable.
 *
 * @param {{
 *   selector: string,
 *   columns: object[],
 *   data?: object[],
 *   order?: Array,
 *   pageLength?: number,
 *   searching?: boolean,
 *   paging?: boolean,
 *   info?: boolean
 * }} config
 *
 * @returns {object}
 */
export function createClientTable(
    config
) {
    const {
        selector,

        columns,

        data = [],

        order = [],

        pageLength = 10,

        searching = true,

        paging = true,

        info = true,

    } = config;


    return new DataTable(
        selector,
        {
            ...BASE_OPTIONS,

            data,

            columns,

            order,

            pageLength,

            searching,

            paging,

            info,
        }
    );
}


/**
 * Replace client-side table data.
 *
 * @param {object} table
 * @param {object[]} rows
 */
export function replaceRows(
    table,
    rows
) {
    table.clear();

    if (Array.isArray(rows)) {
        table.rows.add(rows);
    }

    table.draw(false);
}