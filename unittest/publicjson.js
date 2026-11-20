// Tests for custom/asf.js: /publicjson returns post-processed CVE data.
const assert = require('node:assert').strict
const asf = require('../custom/asf.js')

const doc = () => ({
    cveMetadata: { cveId: 'CVE-2024-12345' },
    CNA_private: { state: 'PUBLIC', owner: 'commons' },
    containers: { cna: {
        title: 'Foo bar',
        affected: [{ product: 'Apache Commons Lang', packageURL: 'pkg:maven/org.apache.commons/commons-lang3' }]
    } }
})

function call(id, body) {
    return new Promise((resolve) => {
        const res = {
            locals: { docs: { cve5: { Document: { findOne: async () => (body === undefined ? undefined : { body: body }) } } } },
            json (j) { resolve(j) }
        }
        asf.asfpublicjson({ params: { id: id } }, res)
    })
}

;(async () => {
    const original = doc()
    const out = await call('CVE-2024-12345', original)

    // Private bookkeeping is not part of the public output.
    assert.equal(out.CNA_private, undefined)
    // The title is prefixed with the product names.
    assert.equal(out.containers.cna.title, 'Apache Commons Lang: Foo bar')
    // The legacy identifiers are derived from the Package URL.
    assert.equal(out.containers.cna.affected[0].collectionURL, 'https://repo.maven.apache.org/maven2')
    assert.equal(out.containers.cna.affected[0].packageName, 'org.apache.commons:commons-lang3')

    // The stored record is left untouched.
    assert.equal(original.containers.cna.title, 'Foo bar')
    assert.equal(original.containers.cna.affected[0].collectionURL, undefined)
    assert.equal(original.CNA_private.state, 'PUBLIC')

    // An id that is not a CVE id does not reach the database.
    assert.deepEqual(await call('not-a-cve', original), { error: 'nodoc' })

    console.log('publicjson: all tests passed')
    process.exit(0)
})().catch((err) => { console.error(err); process.exit(1) })
