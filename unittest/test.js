// Mock
document = {
  addEventListener: function() {
  }
}
window = {
}

// System under test
const assert = require('node:assert').strict
sut = require("../default/cve5/script.js")
// Required with no globals set, deliberately: custom/cve5/script.js must
// resolve packageurl-js on its own (see purlParserClass), because
// customRoutes/publishcve.js requires it the same way.
const purl = require("../custom/cve5/script.js")
const textUtil = require("../src/js/edit/util.js")
// reduceJSON reaches the derivation as a browser global; publishcve.js does this too.
global.purlToLegacyIdentifiers = purl.purlToLegacyIdentifiers

// Tests
assert(sut.htmltoText('<a href="foo">foo</a>') == "foo")
assert(sut.htmltoText('<a href="foo">bar</a>') == "bar foo")
assert(sut.htmltoText('<a href="foo">foo</a> <a href="bar">bar</a>') == "foo   bar")
assert(sut.htmltoText('<a href="foo">baz</a> <a href="bar">bar</a>') == "baz foo   bar")

assert(sut.htmltoText('<a href="foo">foo<br></a>bar') == "foo\n bar")

// purlToLegacyIdentifiers: inputs mirror cases from the official purl test
// suite at package-url/purl-spec (tests/spec + tests/types).
const legacy = purl.purlToLegacyIdentifiers

// Maven uses groupId:artifactId, as the ASF packageName validator requires.
assert.deepEqual(legacy('pkg:maven/org.apache.commons/commons-lang3'), {
  collectionURL: 'https://repo.maven.apache.org/maven2',
  packageName: 'org.apache.commons:commons-lang3'
})
// Percent-decoded npm scope, and the version is dropped.
assert.deepEqual(legacy('pkg:npm/%40angular/animation@12.3.1'), {
  collectionURL: 'https://registry.npmjs.org',
  packageName: '@angular/animation'
})
// An optional namespace that is absent falls back to the bare name.
assert.deepEqual(legacy('pkg:npm/foobar'), {
  collectionURL: 'https://registry.npmjs.org',
  packageName: 'foobar'
})
assert.deepEqual(legacy('pkg:docker/cassandra'), {
  collectionURL: 'https://hub.docker.com',
  packageName: 'cassandra'
})
// Multi-segment namespace kept, subpath dropped.
assert.deepEqual(legacy('pkg:golang/google.golang.org/genproto#googleapis/api/annotations'), {
  collectionURL: 'https://golang.org/pkg',
  packageName: 'google.golang.org/genproto'
})
// Name normalized to lower case by the purl type rules.
assert.deepEqual(legacy('pkg:pypi/Django'), {
  collectionURL: 'https://pypi.python.org',
  packageName: 'django'
})
// Distro types pick the collection URL from the namespace; qualifiers dropped.
assert.deepEqual(legacy('pkg:deb/debian/curl?arch=i386&distro=jessie'), {
  collectionURL: 'https://packages.debian.org',
  packageName: 'curl'
})
assert.deepEqual(legacy('pkg:rpm/opensuse/curl'), {
  collectionURL: 'https://software.opensuse.org',
  packageName: 'curl'
})

// Nothing is derived when there is no well-known package collection.
assert(legacy('pkg:deb/mydistro/curl') === null)   // unmapped distro
assert(legacy('pkg:generic/openssl') === null)     // instance-specific
assert(legacy('pkg:oci/debian') === null)          // registry-specific
assert(legacy('pkg:notatype/foo/bar') === null)    // unregistered type

// Invalid or incomplete input is silently ignored.
assert(legacy('pkg:maven/commons-lang3') === null) // maven requires a groupId
assert(legacy('not-a-purl') === null)
assert(legacy('') === null)
assert(legacy(undefined) === null)

// Guards the silent-null trap: parsePurl swallows a missing PackageURL in its
// own try/catch, so a broken server-side resolution would not throw - it would
// just stop deriving, and every published record would quietly lose the fields.
assert(purl.parsePurl('pkg:maven/g/a') !== null,
  'purl parsing must work in plain Node, with no browser globals set')

// reduceJSON derives the legacy identifiers when the record is serialised.
// It is the only place they are produced: the CVE-JSON tab and
// customRoutes/publishcve.js both go through it.
global.getProductListNoVendor = (c) => c.containers.cna.affected.map(a => a.product).join(', ')

const serialise = (affected) => textUtil.reduceJSON({
  cveMetadata: { cveId: 'CVE-2024-0001' },
  CNA_private: { state: 'READY' },
  containers: { cna: { title: 'Apache Example: something', affected: affected } }
}).containers.cna.affected

// Derived when absent.
assert.deepEqual(serialise([{ product: 'A', packageURL: 'pkg:maven/org.apache.commons/commons-lang3' }]),
  [{ product: 'A', packageURL: 'pkg:maven/org.apache.commons/commons-lang3',
     collectionURL: 'https://repo.maven.apache.org/maven2',
     packageName: 'org.apache.commons:commons-lang3' }])

// An unmappable type adds nothing.
assert.deepEqual(serialise([{ product: 'B', packageURL: 'pkg:generic/openssl' }]),
  [{ product: 'B', packageURL: 'pkg:generic/openssl' }])

// No purl, nothing to do.
assert.deepEqual(serialise([{ product: 'C' }]), [{ product: 'C' }])

// Already carries the fields: left alone, even when they disagree with the purl.
// Publishing must not rewrite authored data - the editor reports the mismatch.
assert.deepEqual(serialise([{ product: 'D', packageURL: 'pkg:pypi/django',
                              collectionURL: 'https://example.org', packageName: 'kept' }]),
  [{ product: 'D', packageURL: 'pkg:pypi/django',
     collectionURL: 'https://example.org', packageName: 'kept' }])

// A half-filled pair is also left alone rather than half-derived.
assert.deepEqual(serialise([{ product: 'E', packageURL: 'pkg:pypi/django', packageName: 'kept' }]),
  [{ product: 'E', packageURL: 'pkg:pypi/django', packageName: 'kept' }])

// The caller's document is never mutated.
const original = { product: 'F', packageURL: 'pkg:pypi/django' }
serialise([original])
assert(original.collectionURL === undefined && original.packageName === undefined)

// CNA_private is still stripped, and the title still prefixed.
const published = textUtil.reduceJSON({
  CNA_private: { state: 'READY' },
  containers: { cna: { title: 'Something', affected: [{ product: 'Alpha' }] } }
})
assert(published.CNA_private === undefined)
assert(published.containers.cna.title === 'Alpha: Something')
