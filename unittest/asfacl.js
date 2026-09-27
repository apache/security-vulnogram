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
assert.equal(asf.asfdocacl('cve5', null, ['airflow']), false)
assert.equal(asf.asfdocacl('cve5', null, [admin]), true)
// Sections without PMC ownership are not restricted.
assert.equal(asf.asfdocacl('cvss4', rec('tomcat'), ['airflow']), true)

assert.deepEqual(asf.asfownerquery('cve5', ['airflow', 'tomcat']),
    { 'body.CNA_private.owner': { '$in': ['airflow', 'tomcat'] } })
assert.deepEqual(asf.asfownerquery('cve5', ['airflow', admin]), {})
assert.deepEqual(asf.asfownerquery('nvd', ['airflow']), {})

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

console.log('asfacl: all tests passed')
