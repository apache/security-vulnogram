// The list table tells Tablesort how to order date cells. Their visible text is
// a friendly date, so without data-sort the column sorts alphabetically.
const assert = require('node:assert').strict
const path = require('node:path')
const pug = require('pug')

const root = path.join(__dirname, '..')
const render = pug.compile(
    'include util.pug\n+table(docs, columns, false, "t")',
    {filename: path.join(root, 'views', 'table-test.pug'), basedir: root}
)

const html = render({
    docs: [
        {ID: '1', updated: new Date('2026-10-28T14:43:00Z'), name: 'second'},
        {ID: '2', updated: new Date('2026-10-27T09:00:00Z'), name: 'first'}
    ],
    columns: ['updated', 'name'],
    fields: {updated: {path: 'updatedAt'}, name: {}},
    pages: 1,
    query: {},
    rowCount: 0,
    textUtil: null
})

assert(html.includes('data-sort="2026-10-28T14:43:00.000Z"'))
assert(html.includes('data-sort="2026-10-27T09:00:00.000Z"'))
// the visible value stays the friendly date
assert(html.includes('>2026-10-28</span>'))
// non-date columns keep their text-based ordering
assert(!/class="name"[^>]*data-sort/.test(html))
