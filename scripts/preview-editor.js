#!/usr/bin/env node

// Serves the document editor UI on its own, with no MongoDB, no login and no
// CVE Services. Intended for working on the editor front end - the schema, the
// json-editor extensions in preload.js, and the inlined script.js.
//
// Everything the real app would fetch from the database is stubbed:
// the document starts empty (or comes from --json), the user is a fixture, and
// the realtime socket is a no-op. Saving, publishing and comments do nothing.
//
//   node ./scripts/preview-editor.js
//   node ./scripts/preview-editor.js --port 8080 --set cve5 --json some-cve.json
//
// Then open the printed URL.

const http = require('http');
const fs = require('fs');
const path = require('path');

// config/conf.js reads the production Let's Encrypt certificates unless told
// otherwise, and this preview never serves TLS.
if (!('VULNOGRAM_TLS_ENABLED' in process.env)) {
    process.env.VULNOGRAM_TLS_ENABLED = 'false';
}

const repoRoot = path.resolve(__dirname, '..');
process.chdir(repoRoot);

const pug = require('pug');
const optSet = require(path.join(repoRoot, 'models/set.js'));
const conf = require(path.join(repoRoot, 'config/conf.js'));
const textUtil = require(path.join(repoRoot, 'src/js/edit/util.js'));

function parseArgs(argv) {
    const args = { set: 'cve5', port: 8199, json: null };
    for (let i = 0; i < argv.length; i++) {
        const next = argv[i + 1];
        if (argv[i] === '--set' && next) { args.set = next; i++; }
        else if (argv[i] === '--port' && next) { args.port = parseInt(next, 10); i++; }
        else if (argv[i] === '--json' && next) { args.json = next; i++; }
        else if (argv[i] === '--help' || argv[i] === '-h') { args.help = true; }
    }
    return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
    process.stdout.write(
        'Usage: node ./scripts/preview-editor.js [--set cve5] [--port 8199] [--json file.json]\n');
    process.exit(0);
}

// Re-reading the section config on every request is what makes editing the
// schema, preload.js or script.js a matter of reloading the page.
function loadOpts() {
    Object.keys(require.cache).forEach(function (file) {
        if (file.startsWith(repoRoot) && file.indexOf('node_modules') === -1) {
            delete require.cache[file];
        }
    });
    return require(path.join(repoRoot, 'models/set.js'))(args.set);
}

let opts = optSet(args.set);
const initialDoc = args.json
    ? { body: JSON.parse(fs.readFileSync(path.resolve(args.json), 'utf8')) }
    : null;

// A stand-in for the logged-in user. `pmcs` gates the ASF templates; include
// `security` so the whole UI is reachable.
const previewUser = {
    username: 'preview',
    name: 'Preview User',
    group: 'preview',
    pmcs: ['security'],
    emoji: ''
};

function renderPage() {
    // opts.edit is a pug path relative to views/, e.g. '../custom/cve5/edit'.
    const template = path.join(repoRoot, 'views', opts.edit + '.pug');
    return pug.renderFile(template, {
        basedir: repoRoot,
        cache: false,
        compileDebug: false,
        pugLib: pug,
        conf: Object.assign({}, conf, { basedir: '/' }),
        confOpts: { [args.set]: opts },
        schemaName: args.set,
        opts: opts,
        min: false,
        title: 'Preview',
        doc: initialDoc,
        doc_id: '',
        idpath: opts.jsonidpath,
        textUtil: textUtil,
        csrfToken: 'preview',
        allowAjax: true,
        ucomments: [],
        user: previewUser,
        messages: function () { return ''; }
    });
}

const contentTypes = {
    '.js': 'text/javascript',
    '.mjs': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.html': 'text/html'
};

function sendFile(res, file) {
    res.writeHead(200, { 'Content-Type': contentTypes[path.extname(file)] || 'application/octet-stream' });
    res.end(fs.readFileSync(file));
}

const server = http.createServer(function (req, res) {
    const url = req.url.split('?')[0];

    try {
        if (url === '/' || url === '/index.html') {
            opts = loadOpts();
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return res.end(renderPage());
        }

        if (url === '/' + args.set + '/schema.js') {
            res.writeHead(200, { 'Content-Type': 'text/javascript' });
            return res.end('docSchema = ' + JSON.stringify(opts.schema));
        }

        // The owner field resolves this $ref over ajax; the real route needs a
        // database and a session.
        if (url === '/users/list/json') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                default: previewUser.username,
                enum: [previewUser.username],
                options: { enum_titles: [previewUser.name] }
            }));
        }
        if (url === '/users/list/css') {
            res.writeHead(200, { 'Content-Type': 'text/css' });
            return res.end('');
        }

        // No socket.io server here; hand back a client that never connects.
        if (url === '/socket.io/socket.io.js') {
            res.writeHead(200, { 'Content-Type': 'text/javascript' });
            return res.end('window.io = function () { return { on: function () {},' +
                ' emit: function () {}, disconnect: function () {}, connected: false }; };');
        }

        // The section's static/ dir. The real app mounts it under
        // /<set>/static/, and the page is served from /<set>/<id>, so relative
        // imports like './static/cvss40.js' also arrive here as /static/...
        if (opts.static) {
            const staticRoot = path.join(repoRoot, opts.static);
            const prefixes = ['/' + args.set + '/static/', '/static/'];
            for (let i = 0; i < prefixes.length; i++) {
                if (url.indexOf(prefixes[i]) === 0) {
                    const staticFile = path.join(staticRoot, url.slice(prefixes[i].length));
                    if (staticFile.startsWith(staticRoot) && fs.existsSync(staticFile)) {
                        return sendFile(res, staticFile);
                    }
                }
            }
        }

        const publicFile = path.join(repoRoot, 'public', url);
        if (publicFile.startsWith(path.join(repoRoot, 'public')) &&
            fs.existsSync(publicFile) && fs.statSync(publicFile).isFile()) {
            return sendFile(res, publicFile);
        }

        // Saves, publishes and comments land here and are intentionally inert.
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end('{}');
    } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(String(e && e.stack ? e.stack : e));
    }
});

server.listen(args.port, '127.0.0.1', function () {
    process.stdout.write('Editor preview for "' + args.set + '" (no database) on ' +
        'http://127.0.0.1:' + args.port + '/\n');
    process.stdout.write('Reload the page to pick up schema/template/script changes.\n');
});
