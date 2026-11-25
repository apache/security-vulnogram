const assert = require('node:assert').strict
const fs = require('node:fs')
const path = require('node:path')

const schema = JSON.parse(fs.readFileSync(
    path.join(__dirname, '../default/cve5/cve5.schema.json'), 'utf8'))

const patterns = []
const collect = (node) => {
    if (!node || typeof node !== 'object') return
    if (typeof node.pattern === 'string') patterns.push(node.pattern)
    for (const key of Object.keys(node)) collect(node[key])
}
collect(schema)

assert(patterns.length > 0, 'no patterns found in the schema')
for (const pattern of patterns) {
    assert.doesNotThrow(() => new RegExp(pattern, 'v'),
        'pattern does not compile with the v flag: ' + pattern)
}
