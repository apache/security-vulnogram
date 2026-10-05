// Tests for custom/tokenauthorize.js: browser-approved, scoped API tokens.
const assert = require('node:assert').strict
const crypto = require('crypto')
const conf = require('../config/conf')
const ta = require('../custom/tokenauthorize.js')

const verifier = crypto.randomBytes(48).toString('base64url') // 64 chars
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
const user = { username: 'alice', pmcs: ['airflow', 'magpie'] }
const admin = { username: 'sec', pmcs: [conf.admingroupname] }
const params = {
  pmc: 'airflow',
  scope: 'write',
  redirect_uri: 'http://127.0.0.1:53682/callback',
  state: 'xyz',
  code_challenge: challenge,
  code_challenge_method: 'S256'
}
const withParam = (k, v) => Object.assign({}, params, { [k]: v })

// validateRedirectUri: loopback IP literals over http, with a port, only.
assert.equal(ta.validateRedirectUri('http://127.0.0.1:53682/callback'), 'http://127.0.0.1:53682/callback')
assert.equal(ta.validateRedirectUri('http://[::1]:53682/'), 'http://[::1]:53682/')
assert.equal(ta.validateRedirectUri('http://localhost:53682/'), null)
assert.equal(ta.validateRedirectUri('https://127.0.0.1:53682/'), null)
assert.equal(ta.validateRedirectUri('http://127.0.0.1/'), null)
assert.equal(ta.validateRedirectUri('http://127.0.0.1.evil.example:53682/'), null)
assert.equal(ta.validateRedirectUri('http://user:pw@127.0.0.1:53682/'), null)
assert.equal(ta.validateRedirectUri('http://127.0.0.1:53682/#frag'), null)
assert.equal(ta.validateRedirectUri('https://evil.example/'), null)
assert.equal(ta.validateRedirectUri('not a url'), null)
assert.equal(ta.validateRedirectUri(undefined), null)

// validateAuthorizeRequest
const ok = ta.validateAuthorizeRequest(params, user)
assert.equal(ok.error, undefined)
assert.deepEqual(ok.request, {
  pmc: 'airflow',
  scope: 'write',
  redirectUri: 'http://127.0.0.1:53682/callback',
  state: 'xyz',
  codeChallenge: challenge
})
assert.equal(ta.validateAuthorizeRequest(withParam('scope', 'read'), user).request.scope, 'read')
// Not a member of the PMC; the security team may ask for any PMC.
assert.match(ta.validateAuthorizeRequest(withParam('pmc', 'kafka'), user).error, /not a member/)
assert.equal(ta.validateAuthorizeRequest(withParam('pmc', 'kafka'), admin).request.pmc, 'kafka')
assert.match(ta.validateAuthorizeRequest(withParam('pmc', 'Air flow'), user).error, /pmc/)
assert.match(ta.validateAuthorizeRequest(withParam('pmc', undefined), user).error, /pmc/)
assert.equal(ta.validateAuthorizeRequest(withParam('scope', 'allocate'), user).request.scope, 'allocate')
assert.match(ta.validateAuthorizeRequest(withParam('scope', 'admin'), user).error, /scope/)
assert.match(ta.validateAuthorizeRequest(withParam('redirect_uri', 'https://evil.example/'), user).error, /redirect_uri/)
assert.match(ta.validateAuthorizeRequest(withParam('state', ''), user).error, /state/)
assert.match(ta.validateAuthorizeRequest(withParam('state', 'a b'), user).error, /state/)
assert.match(ta.validateAuthorizeRequest(withParam('code_challenge_method', 'plain'), user).error, /S256/)
assert.match(ta.validateAuthorizeRequest(withParam('code_challenge', 'short'), user).error, /code_challenge/)
assert.match(ta.validateAuthorizeRequest(undefined, user).error, /pmc/)
assert.match(ta.validateAuthorizeRequest(params, undefined).error, /not a member/)

// issueCode registers the token in the session map ensureAuthenticated scans.
const session = {}
const code = ta.issueCode(session, ok.request)
const token = session.tokens.airflow.write
assert.match(token, /^[0-9a-f-]{36}$/)
// A second approval in the same session reuses the token.
const code2 = ta.issueCode(session, ok.request)
assert.equal(session.tokens.airflow.write, token)
assert.notEqual(code, code2)
// Existing tokens for other PMCs / scopes are left alone.
const session2 = { tokens: { magpie: { read: 'keep-me' } } }
ta.issueCode(session2, ok.request)
assert.equal(session2.tokens.magpie.read, 'keep-me')

// redeemCode: right verifier, once.
assert.deepEqual(ta.redeemCode(code, verifier), { token: token, pmc: 'airflow', scope: 'write' })
assert.equal(ta.redeemCode(code, verifier), null)
// A wrong verifier fails and spends the code.
const wrong = crypto.randomBytes(48).toString('base64url')
assert.equal(ta.redeemCode(code2, wrong), null)
assert.equal(ta.redeemCode(code2, verifier), null)
// Expired codes fail.
const now = Date.now()
const code3 = ta.issueCode({}, ok.request, now)
assert.equal(ta.redeemCode(code3, verifier, now + 61 * 1000), null)
const code4 = ta.issueCode({}, ok.request, now)
assert.equal(ta.redeemCode(code4, verifier, now + 59 * 1000).pmc, 'airflow')
// Malformed input.
assert.equal(ta.redeemCode('no-such-code', verifier), null)
assert.equal(ta.redeemCode(undefined, verifier), null)
const code5 = ta.issueCode({}, ok.request)
assert.equal(ta.redeemCode(code5, 'short'), null)

// checkScopedToken
assert.equal(ta.checkScopedToken('write', 'POST', '/cve5/CVE-2026-1234'), null)
assert.equal(ta.checkScopedToken('write', 'GET', '/cve5/json/CVE-2026-1234'), null)
assert.match(ta.checkScopedToken('write', 'POST', '/allocatecve'), /write token/)
assert.equal(ta.checkScopedToken('read', 'GET', '/cve5/json/CVE-2026-1234'), null)
assert.equal(ta.checkScopedToken('read', 'GET', '/cve5/CVE-2026-1234'), null)
assert.equal(ta.checkScopedToken('read', 'HEAD', '/cve5/json/CVE-2026-1234'), null)
assert.match(ta.checkScopedToken('read', 'POST', '/cve5/CVE-2026-1234'), /read token/)
assert.match(ta.checkScopedToken('read', 'GET', '/allocatecve'), /read token/)
assert.equal(ta.checkScopedToken('allocate', 'POST', '/allocatecve'), null)
assert.match(ta.checkScopedToken('allocate', 'POST', '/cve5/CVE-2026-1234'), /allocate token/)

// narrowUser keeps the identity and limits the PMCs, without touching the session's user.
const narrowed = ta.narrowUser(admin, 'airflow')
assert.deepEqual(narrowed, { username: 'sec', pmcs: ['airflow'] })
assert.deepEqual(admin.pmcs, [conf.admingroupname])

console.log('tokenauthorize: all tests passed')
