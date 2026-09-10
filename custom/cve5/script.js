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
    const rule = purlLegacyTypes[purl.type];
    if (!rule) {
        return null;
    }
    // The collection URL is derived from the type and in some cases (deb, rpm) the PURL namespace.
    const collectionURL = typeof rule.collection === 'string'
        ? rule.collection
        : (purl.namespace ? rule.collection[purl.namespace] : undefined);
    if (!collectionURL) {
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

if (typeof exports !== 'undefined') {
    exports.parsePurl = parsePurl;
    exports.purlToLegacyIdentifiers = purlToLegacyIdentifiers;
}
