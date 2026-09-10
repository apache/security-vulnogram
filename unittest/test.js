// Mock
document = {
  addEventListener: function() {
  }
}
window = {
}

// System under test
const assert = require('node:assert').strict
// script.js reaches for PackageURL as a browser global; in the page it comes
// from public/js/packageurl-js.js, which is bundled from this same package.
global.PackageURL = require('packageurl-js').PackageURL
sut = require("../default/cve5/script.js")

// Tests
assert(sut.htmltoText('<a href="foo">foo</a>') == "foo")
assert(sut.htmltoText('<a href="foo">bar</a>') == "bar foo")
assert(sut.htmltoText('<a href="foo">foo</a> <a href="bar">bar</a>') == "foo   bar")
assert(sut.htmltoText('<a href="foo">baz</a> <a href="bar">bar</a>') == "baz foo   bar")

assert(sut.htmltoText('<a href="foo">foo<br></a>bar') == "foo\n bar")

// purlToLegacyIdentifiers: inputs mirror cases from the official purl test
// suite at package-url/purl-spec (tests/spec + tests/types).
const legacy = sut.purlToLegacyIdentifiers

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
