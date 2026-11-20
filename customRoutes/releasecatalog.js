const express = require('express');
const router = express.Router();

const PROJECT = /^[a-z0-9][a-z0-9-]*$/;
const CACHE_MS = 10 * 60 * 1000;
const cache = new Map();

router.get('/latest', async function (req, res) {
    const project = req.query.project;
    if (typeof project !== 'string' || !PROJECT.test(project)) {
        res.status(400).json({ error: 'invalid project' });
        return;
    }
    const cached = cache.get(project);
    if (cached && Date.now() - cached.at < CACHE_MS) {
        res.json({ version: cached.version });
        return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
        const response = await fetch('https://release-catalog.apache.org/' + project + '@latest', {
            headers: { 'Accept': 'application/json' },
            signal: controller.signal
        });
        if (!response.ok) {
            res.status(404).json({ error: 'not found' });
            return;
        }
        const release = await response.json();
        if (!release || typeof release.version !== 'string') {
            res.status(502).json({ error: 'invalid release' });
            return;
        }
        cache.set(project, { version: release.version, at: Date.now() });
        res.json({ version: release.version });
    } catch (error) {
        res.status(502).json({ error: 'release catalog unavailable' });
    } finally {
        clearTimeout(timer);
    }
});

module.exports = router;
