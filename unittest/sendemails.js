// Tests for customRoutes/sendemails.js and the Bcc parsing in email.js.
const assert = require('node:assert').strict
const conf = require('../config/conf')
const email = require('../customRoutes/email.js')

assert.deepEqual(email.parseBcc('a@example.org, b@example.org'), ['a@example.org', 'b@example.org'])
assert.deepEqual(email.parseBcc('a@example.org, A@example.org'), ['a@example.org'])
assert.deepEqual(email.parseBcc('not-an-email, a@example.org'), ['a@example.org'])
assert.deepEqual(email.parseBcc('a@example.org\nBcc: evil@example.org'), [])

const router = require('../customRoutes/sendemails.js').protected
const layer = router.stack.find((l) => l.route && l.route.path == '/' && l.route.methods.post)
const handler = layer.route.stack[layer.route.stack.length - 1].handle

conf.cveapiliveservice = true
const sent = []
email.sendemail = async (info) => { sent.push(info); return 'stub' }

function post(body) {
  return new Promise((resolve) => {
    const req = {
      body: body,
      user: { name: 'Alice', email: 'alice@apache.org' },
      flash () {}
    }
    const res = { render (view) { resolve(view) } }
    handler(req, res)
  })
}

;(async () => {
  const base = {
    emailto1: 'oss@example.org',
    emailto2: 'announce@example.org',
    emailsubject: 'subject',
    emailtext: 'text',
    emailreplyto: 'reply@example.org'
  }

  await post(Object.assign({}, base, { emailbcc: 'reporter@example.org, second@example.org' }))
  assert.equal(sent.length, 2)
  assert.equal(sent[0].to, 'oss@example.org')
  assert.equal(sent[0].bcc, 'reporter@example.org,second@example.org')
  assert.equal(sent[1].bcc, 'security@apache.org')

  sent.length = 0
  await post(base)
  assert.equal(sent[0].bcc, undefined)

  sent.length = 0
  await post(Object.assign({}, base, { emailbcc: 'nope, reporter@example.org, REPORTER@example.org' }))
  assert.equal(sent[0].bcc, 'reporter@example.org')

  console.log('sendemails: all tests passed')
  process.exit(0)
})().catch((err) => { console.error(err); process.exit(1) })
