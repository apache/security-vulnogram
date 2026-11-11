// Tests for the timeline default in custom/cve5/script.js.
const assert = require('node:assert').strict
const { setDefaultTimelineTime } = require('../custom/cve5/script.js')

const timelineRow = (parentPath, timeEditor) => ({
    parent: { path: parentPath },
    path: 'root.containers.cna.timeline.0',
    getEditor (path) {
        assert.equal(path, 'root.containers.cna.timeline.0.time')
        return timeEditor
    }
})

let setValue
const emptyTime = {
    getValue: () => '',
    setValue: (value) => { setValue = value }
}
assert.equal(setDefaultTimelineTime(timelineRow('root.containers.cna.timeline', emptyTime),
    new Date('2026-11-11T12:00:00Z')), true)
assert.equal(setValue, '2026-11-11T12:00:00.000Z')

const filledTime = {
    getValue: () => '2020-01-01T00:00:00Z',
    setValue: () => { throw new Error('must not overwrite an existing time') }
}
assert.equal(setDefaultTimelineTime(timelineRow('root.containers.cna.timeline', filledTime)), false)

assert.equal(setDefaultTimelineTime(timelineRow('root.containers.cna.credits', emptyTime)), false)
assert.equal(setDefaultTimelineTime(null), false)

console.log('timeline: all tests passed')
