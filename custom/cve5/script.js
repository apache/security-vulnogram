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

function releaseCatalogProject(affected) {
    if (!affected || typeof affected.packageURL !== 'string') {
        return '';
    }
    var match = /^pkg:software-id\/apache\.org\/([a-z0-9][a-z0-9-]*)(?:@[^/]*)?$/.exec(affected.packageURL.trim());
    return match ? match[1] : '';
}

function getReleaseCatalogProjects(cve) {
    var projects = [];
    var affected = cve && cve.containers && cve.containers.cna && cve.containers.cna.affected;
    if (!Array.isArray(affected)) {
        return projects;
    }
    for (var product of affected) {
        var project = releaseCatalogProject(product);
        if (project && !projects.includes(project)) {
            projects.push(project);
        }
    }
    return projects;
}

function parseComparableVersion(version) {
    version = String(version);
    if (version === '*') {
        return { parts: [Infinity, Infinity, Infinity], prerelease: [] };
    }
    if (version === '0') {
        return { parts: [0, 0, 0], prerelease: [] };
    }
    var match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version);
    if (!match) {
        return null;
    }
    return {
        parts: [Number(match[1]), Number(match[2]), Number(match[3])],
        prerelease: match[4] ? match[4].split('.') : []
    };
}

function comparePrerelease(left, right) {
    if (left.length === 0 && right.length === 0) {
        return 0;
    }
    if (left.length === 0) {
        return 1;
    }
    if (right.length === 0) {
        return -1;
    }
    var length = Math.min(left.length, right.length);
    for (var i = 0; i < length; i++) {
        var leftNumber = /^\d+$/.test(left[i]) ? Number(left[i]) : null;
        var rightNumber = /^\d+$/.test(right[i]) ? Number(right[i]) : null;
        if (leftNumber !== null && rightNumber !== null) {
            if (leftNumber !== rightNumber) {
                return leftNumber < rightNumber ? -1 : 1;
            }
        } else if (leftNumber !== null) {
            return -1;
        } else if (rightNumber !== null) {
            return 1;
        } else if (left[i] !== right[i]) {
            return left[i] < right[i] ? -1 : 1;
        }
    }
    if (left.length === right.length) {
        return 0;
    }
    return left.length < right.length ? -1 : 1;
}

function compareVersions(left, right) {
    var a = parseComparableVersion(left);
    var b = parseComparableVersion(right);
    if (!a || !b) {
        return null;
    }
    for (var i = 0; i < 3; i++) {
        if (a.parts[i] !== b.parts[i]) {
            return a.parts[i] < b.parts[i] ? -1 : 1;
        }
    }
    return comparePrerelease(a.prerelease, b.prerelease);
}

function versionEntryStatus(entry, latest) {
    if (!entry || typeof entry.version !== 'string') {
        return null;
    }
    var isRange = entry.lessThan !== undefined || entry.lessThanOrEqual !== undefined;
    if (isRange && entry.versionType !== 'semver') {
        return null;
    }
    var matches;
    if (!isRange) {
        matches = entry.versionType === 'semver'
            ? compareVersions(entry.version, latest) === 0
            : entry.version === latest;
    } else {
        var start = compareVersions(entry.version, latest);
        if (start === null) {
            return null;
        }
        if (entry.lessThan !== undefined) {
            var end = compareVersions(latest, entry.lessThan);
            matches = end !== null && start <= 0 && end < 0;
        } else {
            var endInclusive = compareVersions(latest, entry.lessThanOrEqual);
            matches = endInclusive !== null && start <= 0 && endInclusive <= 0;
        }
    }
    if (!matches) {
        return null;
    }
    var status = entry.status;
    if (Array.isArray(entry.changes)) {
        for (var change of entry.changes) {
            if (change && typeof change.at === 'string' && change.status) {
                var at = compareVersions(latest, change.at);
                if (at !== null && at >= 0) {
                    status = change.status;
                }
            }
        }
    }
    return status || 'unknown';
}

function isLatestReleaseAffected(cve, project, latest) {
    var affected = cve && cve.containers && cve.containers.cna && cve.containers.cna.affected;
    if (!Array.isArray(affected)) {
        return false;
    }
    for (var product of affected) {
        if (releaseCatalogProject(product) !== project) {
            continue;
        }
        var versions = Array.isArray(product.versions) ? product.versions : [];
        var status = null;
        for (var entry of versions) {
            status = versionEntryStatus(entry, latest);
            if (status !== null) {
                break;
            }
        }
        if (status === null) {
            status = product.defaultStatus || 'unaffected';
        }
        if (status === 'affected') {
            return true;
        }
    }
    return false;
}

async function showReleaseWarning(cve) {
    var element = document.getElementById('emailwarning');
    if (!element) {
        return;
    }
    element.classList.add('hid');
    element.textContent = '';
    var projects = getReleaseCatalogProjects(cve);
    for (var project of projects) {
        try {
            var response = await fetch('/releasecatalog/latest?project=' + encodeURIComponent(project), {
                headers: { 'Accept': 'application/json' }
            });
            if (!response.ok) {
                continue;
            }
            var release = await response.json();
            if (release && typeof release.version === 'string' && isLatestReleaseAffected(cve, project, release.version)) {
                element.textContent = 'Warning: the latest release ' + release.version + ' is still listed as affected. Add the fixed version before sending these emails.';
                element.classList.remove('hid');
                return;
            }
        } catch (error) {
        }
    }
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

if (typeof exports !== 'undefined') {
    exports.getProductListNoVendor = getProductListNoVendor;
    exports.isGitboxRepo = isGitboxRepo;
    exports.titleNamesProduct = titleNamesProduct;
    exports.getReleaseCatalogProjects = getReleaseCatalogProjects;
    exports.compareVersions = compareVersions;
    exports.isLatestReleaseAffected = isLatestReleaseAffected;
    exports.parsePurl = parsePurl;
    exports.purlToLegacyIdentifiers = purlToLegacyIdentifiers;
}
