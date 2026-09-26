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

console.log('asfacl: all tests passed')
