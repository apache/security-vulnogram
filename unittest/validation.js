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
global.PackageURL = require('packageurl-js').PackageURL
global.purlToLegacyIdentifiers = require('../default/cve5/script.js').purlToLegacyIdentifiers

const productValidator = require('../default/cve5/conf.js').validators[0]
const mismatches = (product) => productValidator({ id: 'pE' }, product, 'root.containers.cna.affected.0')
    .filter(e => e.message === 'Does not match the Package URL')

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

// A stored collectionURL that disagrees with the purl.
const badUrl = mismatches(Object.assign({}, maven, { collectionURL: 'https://pypi.python.org' }))
assert(badUrl.length === 1)
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
