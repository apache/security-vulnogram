const assert = require('node:assert').strict
const unwrapEmailText = require('../custom/cve5/script.js').unwrapEmailText

assert.equal(unwrapEmailText("The client does\nnot close the connection"),
    "The client does not close the connection")
assert.equal(unwrapEmailText("The client does\r\nnot close the connection"),
    "The client does not close the connection")
assert.equal(unwrapEmailText("First paragraph.\n\nSecond paragraph."),
    "First paragraph.\n\nSecond paragraph.")
assert.equal(unwrapEmailText("First paragraph.\n\n\n\nSecond paragraph."),
    "First paragraph.\n\nSecond paragraph.")
assert.equal(unwrapEmailText("Fix:\n* one\n* two"), "Fix:\n* one\n* two")
assert.equal(unwrapEmailText("Steps:\n1. first\n2) second"), "Steps:\n1. first\n2) second")
assert.equal(unwrapEmailText("  padded\n  lines  "), "padded lines")
assert.equal(unwrapEmailText("version\n2 is out"), "version 2 is out")
assert.equal(unwrapEmailText(undefined), "")
