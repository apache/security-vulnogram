const assert = require('node:assert').strict
const conf = require('../config/conf')
const asf = require('../custom/asf.js')

const admin = conf.admingroupname
const rec = (owner) => ({ body: { CNA_private: owner ? { owner } : {} } })

// Records of owned sections are visible to their PMC and the security team only.
assert.equal(asf.asfdocacl('cve5', rec('airflow'), ['airflow']), true)
assert.equal(asf.asfdocacl('cve5', rec('tomcat'), ['airflow']), false)
assert.equal(asf.asfdocacl('cve5', rec('tomcat'), [admin]), true)
assert.equal(asf.asfdocacl('cve', rec('tomcat'), ['airflow']), false)
// No owner, or no record: security team only.
assert.equal(asf.asfdocacl('cve5', rec(), ['airflow']), false)
assert.equal(asf.asfdocacl('cve5', rec(), [admin]), true)
assert.equal(asf.asfdocacl('cve5', null, ['airflow']), false)
assert.equal(asf.asfdocacl('cve5', null, [admin]), true)
// Sections without PMC ownership are not restricted.
assert.equal(asf.asfdocacl('cvss4', rec('tomcat'), ['airflow']), true)

assert.deepEqual(asf.asfownerquery('cve5', ['airflow', 'tomcat']),
    { 'body.CNA_private.owner': { '$in': ['airflow', 'tomcat'] } })
assert.deepEqual(asf.asfownerquery('cve5', ['airflow', admin]), {})
assert.deepEqual(asf.asfownerquery('nvd', ['airflow']), {})

assert.equal(asf.ownerCleared(rec('airflow').body, rec('airflow').body), false)
assert.equal(asf.ownerCleared(rec('airflow').body, rec('tomcat').body), false)
assert.equal(asf.ownerCleared(rec('airflow').body, rec().body), true)
assert.equal(asf.ownerCleared(rec('airflow').body, {}), true)

// asfdocacl and asfownerquery encode the same rule and must agree.
const matches = (query, doc) => {
    const cond = query['body.CNA_private.owner']
    return cond === undefined || cond['$in'].includes(doc.body.CNA_private.owner)
}
for (const section of ['cve', 'cve5', 'cvss4', 'nvd']) {
    for (const owner of ['airflow', 'tomcat', admin, undefined]) {
        for (const pmcs of [['airflow'], ['airflow', 'tomcat'], [admin], ['airflow', admin], []]) {
            assert.equal(matches(asf.asfownerquery(section, pmcs), rec(owner)),
                asf.asfdocacl(section, rec(owner), pmcs),
                `${section} owner=${owner} pmcs=${pmcs}`)
        }
    }
}

const emailList = (pmc) => new Promise((resolve) => asf.getemaillistforpmc(pmc, resolve))
const withFetch = async (impl, fn) => {
    const original = global.fetch
    global.fetch = impl
    try { return await fn() } finally { global.fetch = original }
}

;(async () => {
    // The PMC mailing list lookup falls back to dev@ unless the API names a
    // better list, and it always calls back exactly once.
    assert.equal(await withFetch(
        async () => ({ status: 200, json: async () => ({ lists: { 'airflow.apache.org': { announce: true } } }) }),
        () => emailList('airflow')), 'announce@airflow.apache.org')
    assert.equal(await withFetch(
        async () => ({ status: 200, json: async () => ({ lists: {} }) }),
        () => emailList('airflow')), 'dev@airflow.apache.org')
    assert.equal(await withFetch(
        async () => ({ status: 500, json: async () => ({}) }),
        () => emailList('airflow')), 'dev@airflow.apache.org')
    assert.equal(await withFetch(
        async () => { throw new Error('offline') },
        () => emailList('airflow')), 'dev@airflow.apache.org')

    console.log('asfacl: all tests passed')
})().catch((err) => { console.error(err); process.exit(1) })
