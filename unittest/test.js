// Mock
document = {
  addEventListener: function() {
  }
}

// System under test
const assert = require('node:assert').strict
sut = require("../default/cve5/script.js")

// Tests
assert(sut.htmltoText('<a href="foo">foo</a>') == "foo")
assert(sut.htmltoText('<a href="foo">bar</a>') == "bar foo")
assert(sut.htmltoText('<a href="foo">foo</a> <a href="bar">bar</a>') == "foo   bar")
assert(sut.htmltoText('<a href="foo">baz</a> <a href="bar">bar</a>') == "baz foo   bar")

assert(sut.htmltoText('<a href="foo">foo<br></a>bar') == "foo\n bar")
