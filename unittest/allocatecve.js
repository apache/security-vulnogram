// Tests for customRoutes/allocatecve.js: Bearer-token callers get the
// allocated CVE IDs back as JSON.
const assert = require('node:assert').strict
const conf = require('../config/conf')
const email = require('../customRoutes/email.js')
const asf = require('../custom/asf.js')

// Test mode: CVE Services is faked locally and no mail goes out.
conf.cveapiliveservice = false
conf.pmcstrustedascna = ['airflow']
email.sendemail = async () => 'stub'
asf.getemaillistforpmc = (pmc, cb) => cb('private@' + pmc + '.apache.org')

const router = require('../customRoutes/allocatecve.js').protected
const layer = router.stack.find((l) => l.route && l.route.path == '/' && l.route.methods.post)
const handler = layer.route.stack[layer.route.stack.length - 1].handle

function post(body, { bearer = true, insertFails = false, pmcs = ['airflow'] } = {}) {
  return new Promise((resolve) => {
    const out = { status: 200, json: undefined, html: '' }
    const req = {
      body,
      headers: bearer ? { authorization: 'Bearer token' } : {},
      user: { username: 'alice', pmcs },
      token_pmc: bearer ? body.pmc : undefined,
      flash () {}
    }
    const res = {
      locals: { docs: { cve5: { Document: { insertOne: async () => { if (insertFails) throw new Error('db down') } } } } },
      status (code) { out.status = code; return this },
      json (j) { out.json = j; resolve(out); return this },
      write (h) { out.html += h },
      end () { resolve(out) },
      render (view) { out.html = view; resolve(out) }
    }
    handler(req, res)
  })
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/

;(async () => {
  // Success: the allocated ID comes back as JSON.
  let r = await post({ pmc: 'airflow', cvetitle: 'title' })
  assert.equal(r.status, 200)
  assert.equal(r.json.cve_ids.length, 1)
  assert.match(r.json.cve_ids[0], CVE_RE)

  // Blank title: 400, not an HTML page.
  r = await post({ pmc: 'airflow', cvetitle: '' })
  assert.equal(r.status, 400)
  assert.match(r.json.message, /cvetitle/)

  // PMC not trusted as a CNA: the request goes to security@ by mail, no ID yet.
  r = await post({ pmc: 'tomcat', cvetitle: 'title' }, { pmcs: ['tomcat'] })
  assert.equal(r.status, 202)
  assert.deepEqual(r.json.cve_ids, [])

  // Saving the record fails: the reserved ID is still returned.
  r = await post({ pmc: 'airflow', cvetitle: 'title' }, { insertFails: true })
  assert.equal(r.status, 500)
  assert.match(r.json.cve_ids[0], CVE_RE)
  assert.match(r.json.message, /saving the record failed/)

  // The browser form still gets HTML links.
  r = await post({ pmc: 'airflow', cvetitle: 'title' }, { bearer: false })
  assert.equal(r.json, undefined)
  assert.match(r.html, /<a href="\/cve5\/CVE-/)

  console.log('allocatecve: all tests passed')
  process.exit(0)
})().catch((err) => { console.error(err); process.exit(1) })
