// Tests for the ASF post-processing in src/js/edit/util.js.
const assert = require('node:assert').strict
const script = require('../custom/cve5/script.js')
global.getProductListNoVendor = script.getProductListNoVendor
global.purlToLegacyIdentifiers = script.purlToLegacyIdentifiers
const textUtil = require('../src/js/edit/util.js')

const doc = (defect, references) => ({
    cveMetadata: { cveId: 'CVE-2024-1234' },
    CNA_private: { state: 'PUBLIC' },
    containers: { cna: {
        title: 'Example vulnerability',
        affected: [{ product: 'Apache Tomcat' }],
        source: defect === undefined ? {} : { defect: defect },
        references: references
    } }
})

const out = textUtil.reduceJSON(doc(['TOMCAT-522', ' TOMCAT-600 ']))
assert.equal(out.CNA_private, undefined)
assert.equal(out.containers.cna.title, 'Apache Tomcat: Example vulnerability')
const urls = out.containers.cna.references.map((reference) => reference.url)
assert(urls.includes('https://issues.apache.org/jira/browse/TOMCAT-522'))
assert(urls.includes('https://issues.apache.org/jira/browse/TOMCAT-600'))
assert.deepEqual(out.containers.cna.references.find((reference) => reference.url.endsWith('TOMCAT-522')).tags,
    ['issue-tracking'])

const existing = [{ url: 'https://issues.apache.org/jira/browse/TOMCAT-522', tags: ['issue-tracking'] }]
const withExisting = textUtil.reduceJSON(doc(['TOMCAT-522'], existing))
assert.equal(withExisting.containers.cna.references.length, 1)

assert.ok(!textUtil.reduceJSON(doc(undefined, [])).containers.cna.references)

const mixed = textUtil.reduceJSON(doc([null, '  ', 'TOMCAT-1']))
assert.equal(mixed.containers.cna.references.length, 1)
assert.equal(mixed.containers.cna.references[0].url, 'https://issues.apache.org/jira/browse/TOMCAT-1')

console.log('reducejson: all tests passed')
