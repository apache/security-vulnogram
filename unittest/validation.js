const assert = require('node:assert').strict
sut = require("../custom/cve5/conf.js")

customValidators = sut.validators[1]

assert.deepEqual(customValidators(undefined, "user@pulsar.apache.org", "root.CNA_private.userslist"), [], "user list should not produce an error")
assert(customValidators(undefined, "security@pulsar.apache.org", "root.CNA_private.userslist")[0].message.endsWith("Mixing public and private lists is discouraged."))
assert(customValidators(undefined, "private@pulsar.apache.org", "root.CNA_private.userslist")[0].message.endsWith("Mixing public and private lists is discouraged."))

// The 'pE' (product entry) validator reports a stored record whose legacy
// identifiers disagree with its Package URL. In the browser the derivation
// helper is a global from default/cve5/script.js; mock its dependencies the
// same way unittest/test.js does.
document = { addEventListener: function () {} }
window = {}
// The validator reaches these as browser globals; on the page they come from
// custom/cve5/script.js, inlined into opts.script.
global.parsePurl = require('../custom/cve5/script.js').parsePurl
global.purlToLegacyIdentifiers = require('../custom/cve5/script.js').purlToLegacyIdentifiers

// The purl checks now live in the ASF validator, not the default one.
const productValidator = require('../custom/cve5/conf.js').validators[1]
const mismatches = (product) => productValidator({ id: 'pE' }, product, 'root.containers.cna.affected.0')
    .filter(e => e.message.startsWith('Does not match the Package URL'))

const maven = {
  vendor: 'Apache Software Foundation',
  product: 'Commons Lang',
  packageURL: 'pkg:maven/org.apache.commons/commons-lang3',
  collectionURL: 'https://repo.maven.apache.org/maven2',
  packageName: 'org.apache.commons:commons-lang3'
}

// Consistent record: nothing to report.
assert.deepEqual(mismatches(maven), [])

// Legacy fields left empty are not a mismatch; the vendor/product rule covers those.
assert.deepEqual(mismatches(Object.assign({}, maven, { collectionURL: undefined, packageName: undefined })), [])

// A stored packageName that disagrees with the purl.
const badName = mismatches(Object.assign({}, maven, { packageName: 'commons-lang3' }))
assert(badName.length === 1)
assert(badName[0].path === 'root.containers.cna.affected.0.packageName')
assert(badName[0].message.includes('org.apache.commons:commons-lang3'))

// A stored collectionURL that disagrees with the purl.
const badUrl = mismatches(Object.assign({}, maven, { collectionURL: 'https://pypi.python.org' }))
assert(badUrl.length === 1)
const expectedRepoUrlMatch = badUrl[0].message.match(/https?:\/\/[^\s)]+/)
assert(expectedRepoUrlMatch, 'expected mismatch message to contain a URL')
const expectedRepoUrl = new URL(expectedRepoUrlMatch[0])
assert(expectedRepoUrl.protocol === 'https:')
assert(expectedRepoUrl.host === 'repo.maven.apache.org')
assert(expectedRepoUrl.pathname === '/maven2')
assert(badUrl[0].path === 'root.containers.cna.affected.0.collectionURL')

// Both wrong at once.
assert(mismatches(Object.assign({}, maven, { collectionURL: 'https://pypi.python.org', packageName: 'nope' })).length === 2)

// A purl we deliberately do not map derives nothing, so it can never mismatch.
assert.deepEqual(mismatches({
  vendor: 'n/a', product: 'n/a',
  packageURL: 'pkg:generic/openssl',
  collectionURL: 'https://example.org/packages',
  packageName: 'openssl'
}), [])

// No purl at all: the legacy fields are the only source of truth.
assert.deepEqual(mismatches({
  vendor: 'n/a', product: 'n/a',
  collectionURL: 'https://pypi.python.org', packageName: 'django'
}), [])

// The CVE 5 schema: "The Package URL MUST NOT include a version."
const versionErrors = (product) => productValidator({ id: 'pE' }, product, 'root.containers.cna.affected.0')
    .filter(e => e.message === 'The Package URL must not include a version')

const versioned = Object.assign({}, maven, {
  packageURL: 'pkg:maven/org.apache.commons/commons-lang3@3.12.0'
})

// A version is reported...
const versionErr = versionErrors(versioned)
assert(versionErr.length === 1)
assert(versionErr[0].path === 'root.containers.cna.affected.0.packageURL')

// ...but the legacy identifiers are still derived from it, so a versioned purl
// does not also produce a spurious mismatch.
assert.deepEqual(mismatches(versioned), [])

// Without a version there is nothing to report.
assert.deepEqual(versionErrors(maven), [])

// Qualifiers and a subpath are legitimate; only the version is forbidden.
assert.deepEqual(versionErrors(Object.assign({}, maven, {
  packageURL: 'pkg:maven/org.apache.commons/commons-lang3?type=pom'
})), [])
assert.deepEqual(versionErrors({
  vendor: 'ASF', product: 'X',
  packageURL: 'pkg:golang/google.golang.org/genproto#googleapis/api/annotations',
  collectionURL: 'https://golang.org/pkg', packageName: 'google.golang.org/genproto'
}), [])

// Not a purl at all: no version complaint.
assert.deepEqual(versionErrors(Object.assign({}, maven, { packageURL: 'not-a-purl' })), [])
