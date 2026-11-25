// Package URL -> the legacy CVE 5.x identifiers (collectionURL + packageName).
const purlLegacyTypes = {
    'alpm': {collection: 'https://archlinux.org/packages', name: 'name'},
    'apk': {collection: 'https://pkgs.alpinelinux.org', name: 'name'},
    'bazel': {collection: 'https://bcr.bazel.build', name: 'name'},
    'bitbucket': {collection: 'https://bitbucket.org', name: 'path'},
    'bitnami': {collection: 'https://downloads.bitnami.com/files/stacksmith', name: 'name'},
    'brew': {collection: 'https://brew.sh/', name: 'path'},
    'cargo': {collection: 'https://crates.io', name: 'name'},
    'chrome-extension': {collection: 'https://chrome.google.com/webstore', name: 'name'},
    'cocoapods': {collection: 'https://cocoapods.org', name: 'name'},
    'composer': {collection: 'https://packagist.org', name: 'path'},
    'conan': {collection: 'https://conan.io/center', name: 'path'},
    'conda': {collection: 'https://anaconda.org/anaconda/repo', name: 'name'},
    'cpan': {collection: 'https://cpan.org/modules', name: 'name'},
    'cran': {collection: 'https://cran.r-project.org', name: 'name'},
    'deb': {
        collection: {
            'debian': 'https://packages.debian.org',
            'ubuntu': 'https://packages.ubuntu.com'
        },
        name: 'name'
    },
    'docker': {collection: 'https://hub.docker.com', name: 'path'},
    'gem': {collection: 'https://rubygems.org', name: 'name'},
    'github': {collection: 'https://github.com', name: 'path'},
    'gitlab': {collection: 'https://gitlab.com/explore', name: 'path'},
    'golang': {collection: 'https://golang.org/pkg', name: 'path'},
    'hackage': {collection: 'https://hackage.haskell.org', name: 'name'},
    'hex': {collection: 'https://repo.hex.pm', name: 'name'},
    'huggingface': {collection: 'https://huggingface.co', name: 'path'},
    'julia': {collection: 'https://juliahub.com', name: 'name'},
    'luarocks': {collection: 'https://luarocks.org', name: 'path'},
    'maven': {collection: 'https://repo.maven.apache.org/maven2', name: 'group'},
    'npm': {collection: 'https://registry.npmjs.org', name: 'path'},
    'nuget': {collection: 'https://nuget.org/packages', name: 'name'},
    'opam': {collection: 'https://opam.ocaml.org/packages', name: 'name'},
    'pub': {collection: 'https://pub.dev', name: 'name'},
    'pypi': {collection: 'https://pypi.python.org', name: 'name'},
    'rpm': {
        collection: {
            'redhat': 'https://access.redhat.com/downloads/content/package-browser',
            'fedora': 'https://packages.fedoraproject.org',
            'opensuse': 'https://software.opensuse.org',
            'suse': 'https://software.opensuse.org'
        },
        name: 'name'
    },
    'vcpkg': {collection: 'https://github.com/microsoft/vcpkg', name: 'name'},
    'vscode-extension': {collection: 'https://marketplace.visualstudio.com', name: 'path'}
};

// The purl type and namespace come from the user. A type is letters, digits,
// '.', '+' and '-', so "constructor" is a valid one, and a namespace may be
// anything, "__proto__" included. Look the tables up by own key only, or
// pkg:constructor/x finds Object.prototype.constructor.
function ownEntry(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

// Returns a parsed PackageURL, or null when the string is not a purl (yet)
function purlParserClass() {
    if (typeof PackageURL !== 'undefined') {
        return PackageURL;
    }
    if (typeof require === 'function') {
        return require('packageurl-js').PackageURL;
    }
    return null;
}

function parsePurl(purlString) {
    const parser = purlString && purlParserClass();
    if (!parser) {
        return null;
    }
    try {
        return parser.fromString(String(purlString).trim());
    } catch (e) {
        return null;
    }
}

// Returns {collectionURL, packageName}, or null when nothing can be derived.
function purlToLegacyIdentifiers(purlString) {
    const purl = parsePurl(purlString);
    if (!purl) {
        return null;
    }
    const rule = ownEntry(purlLegacyTypes, purl.type);
    if (!rule) {
        return null;
    }
    // The collection URL is derived from the type and in some cases (deb, rpm) the PURL namespace.
    const collectionURL = typeof rule.collection === 'string'
        ? rule.collection
        : (purl.namespace ? ownEntry(rule.collection, purl.namespace) : undefined);
    if (typeof collectionURL !== 'string' || !collectionURL) {
        return null;
    }
    // Types whose namespace is optional (npm scopes, docker/conan/brew/luarocks
    // namespaces) fall back to the bare name; packageurl-js has already
    // rejected a missing namespace for the types that require one.
    let packageName;
    if (rule.name === 'group') {
        if (!purl.namespace) {
            return null;
        }
        packageName = purl.namespace + ':' + purl.name;
    } else if (rule.name === 'path' && purl.namespace) {
        packageName = purl.namespace + '/' + purl.name;
    } else {
        packageName = purl.name;
    }
    return {
        collectionURL: collectionURL,
        packageName: packageName
    };
}

// The distinct product names, prepended to the title when the record is published.
function getProductListNoVendor(cve) {
    var lines = [];
    for (var affected of cve.containers.cna.affected) {
        if (!lines.includes(affected.product)) {
            lines.push(affected.product);
        }
    }
    return lines.join(", ");
}

// Whether the title already names the product, judged by the word "Apache" anywhere in it.
// A whole word is required,
// so that identifiers such as ApacheHttpClient do not count as the product name.
function titleNamesProduct(title) {
    return /\bApache\b/.test(title);
}

// Whether the URL is a cloneable repository on the ASF GitBox: https://gitbox.apache.org/repos/asf/<name>.git.
// The .git suffix is required, as in the git.kernel.org URLs the Linux CNA publishes.
function isGitboxRepo(repo) {
    let url;
    try {
        url = new URL(String(repo).trim());
    } catch (e) {
        return false;
    }
    return url.protocol === 'https:' &&
        url.hostname === 'gitbox.apache.org' &&
        url.port === '' &&
        url.search === '' &&
        url.hash === '' &&
        /^\/repos\/asf\/[^\/]+\.git$/.test(url.pathname);
}

function purlProjectSlug(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/^apache[\s-]+/, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function purlFromLegacyIdentifiers(collectionURL, packageName) {
    if (typeof collectionURL !== 'string' || typeof packageName !== 'string') {
        return null;
    }
    const collection = collectionURL.trim().replace(/\/+$/, '');
    const name = packageName.trim();
    if (!collection || !name) {
        return null;
    }
    for (const type of Object.keys(purlLegacyTypes)) {
        const rule = ownEntry(purlLegacyTypes, type);
        let namespace = null;
        if (typeof rule.collection === 'string') {
            if (rule.collection.replace(/\/+$/, '') === collection) {
                namespace = '';
            }
        } else {
            for (const key of Object.keys(rule.collection)) {
                if (rule.collection[key].replace(/\/+$/, '') === collection) {
                    namespace = key;
                    break;
                }
            }
        }
        if (namespace === null) {
            continue;
        }
        if (rule.name === 'group') {
            const parts = name.split(':');
            if (parts.length !== 2 || !parts[0] || !parts[1]) {
                continue;
            }
            return 'pkg:' + type + '/' + parts[0] + '/' + parts[1];
        }
        if (namespace) {
            return 'pkg:' + type + '/' + namespace + '/' + name;
        }
        return 'pkg:' + type + '/' + name;
    }
    return null;
}

function purlVersionStrings(versions) {
    const out = [];
    for (const version of versions || []) {
        const value = version && version.version;
        if (typeof value === 'string' && value && value !== '0' && value !== '*' &&
            !/[\s@/]/.test(value) && !out.includes(value)) {
            out.push(value);
        }
    }
    return out;
}

function purlSuggestions(record, affected) {
    const out = [];
    const versions = purlVersionStrings(affected && affected.versions);
    const legacy = purlFromLegacyIdentifiers(
        affected && affected.collectionURL, affected && affected.packageName);
    if (legacy) {
        out.push(legacy);
        for (const version of versions) {
            out.push(legacy + '@' + version);
        }
    }
    const owner = record && record.CNA_private && record.CNA_private.owner;
    const slug = purlProjectSlug(affected && affected.product) || purlProjectSlug(owner);
    if (slug) {
        const base = 'pkg:software-id/apache.org/' + slug;
        out.push(base + '@latest');
        for (const version of versions) {
            out.push(base + '@' + version);
        }
    }
    return out.filter((value, index) => out.indexOf(value) === index);
}

if (typeof exports !== 'undefined') {
    exports.getProductListNoVendor = getProductListNoVendor;
    exports.isGitboxRepo = isGitboxRepo;
    exports.titleNamesProduct = titleNamesProduct;
    exports.parsePurl = parsePurl;
    exports.purlToLegacyIdentifiers = purlToLegacyIdentifiers;
    exports.purlFromLegacyIdentifiers = purlFromLegacyIdentifiers;
    exports.purlSuggestions = purlSuggestions;
}
