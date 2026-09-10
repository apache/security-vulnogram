function getProductListNoVendor(cve) {
    var lines = [];
    for (var affected of cve.containers.cna.affected) {
        if (!lines.includes(affected.product)) {
            lines.push(affected.product);
        }
    }
    return lines.join(", ");
}

async function loadProductNames() {
    var projects = []
    var pmcs = userPMCS.split(',');
    var res;
    const abortController = new AbortController()
    setTimeout(() => abortController.abort(), 5000)
    try {
	var response = await fetch('https://whimsy.apache.org/public/committee-info.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error',
	    signal: abortController.signal
	});
	if (!response.ok) {
	    errMsg.textContent = "Failed Apache project list";
	    infoMsg.textContent = "";
	    throw Error(id + ' ' + response.statusText);
	} else {
	    res = await response.json();
	    if (res.committees) {
		for (var committee in res.committees)
		    if (pmcs.includes(committee) || pmcs.includes('security')) {
			res.committees[committee].display_name &&
			    projects.push('Apache ' + res.committees[committee].display_name);
		    }
	    }
	}
    } catch (error) {
	errMsg.textContent = error;
    }
    try {
	    const abortController = new AbortController()
	    setTimeout(() => abortController.abort(), 5000)
	var response = await fetch('https://whimsy.apache.org/public/public_podlings.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error',
	    signal: abortController.signal
	});
	if (!response.ok) {
	    errMsg.textContent = "Failed Apache podling list";
	    infoMsg.textContent = "";
	    throw Error(id + ' ' + response.statusText);
	} else {
	    var resp = await response.json();
	    if (resp.podling) {
		for (var committee in resp.podling) {
		    if (pmcs.includes(committee) || pmcs.includes('security')) {
                        if (resp.podling[committee].status && resp.podling[committee].status == "current") {
			    if (resp.podling[committee].name && !res.committees[committee])
			        projects.push('Apache ' + resp.podling[committee].name + " (incubating)");
                        }
		    }
                }
	    }
	}
    } catch (error) {
	errMsg.textContent = error;
    }
    return (projects);
}


async function loadProjectUrl(pmc) {
    var url = ""
    try {
	    const abortController = new AbortController()
	    setTimeout(() => abortController.abort(), 5000)
	var response = await fetch('https://whimsy.apache.org/public/committee-info.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error',
	    signal: abortController.signal
	});
	if (!response.ok) {
            return url
	} else {
	    var res = await response.json();
	    if (res.committees && res.committees[pmc]) {
                url = res.committees[pmc].site
                return url.replace('http:','https:')
	    }
	}
    } catch (error) {
        return url
    }
    /* If that failed, see if it retired */
    try {
	    const abortController = new AbortController()
	    setTimeout(() => abortController.abort(), 5000)
	var response = await fetch('https://whimsy.apache.org/public/committee-retired.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error',
	    signal: abortController.signal
	});
	if (!response.ok) {
            return url
	} else {
	    var res = await response.json();
	    if (res.retired && res.retired[pmc]) {
                url = 'https://attic.apache.org/projects/' + pmc + '.html'
                return url
	    }
	}
    } catch (error) {
        return url
    }
    /* If that failed, try the podlings */
    try {
	    const abortController = new AbortController()
	    setTimeout(() => abortController.abort(), 5000)
	var response = await fetch('https://whimsy.apache.org/public/public_podlings.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error',
	    signal: abortController.signal
	});
	if (!response.ok) {
            return url
	} else {
	    var res = await response.json();
	    if (res.podling && res.podling[pmc] && res.podling[pmc].podlingStatus && res.podling[pmc].podlingStatus.website) {
                url = res.podling[pmc].podlingStatus.website
                return url.replace('http:','https:')
	    }
	}
    } catch (error) {
        return url
    }    
}

async function loadEmailLists(pmc) {
    try {
       var response = await fetch('/asfemaillists?pmc='+pmc, { method: 'GET' });
       if (response.ok) {
           return await response.text();
       } else {
           return "";
       }
    } catch (error) {
        return "";
    }
}

// The legacy package identifiers (collectionURL + packageName) are not stored:
// packageURL is the single source of truth, and textUtil.reduceJSON derives the
// pair when the record is serialized for publication.
JSONEditor.defaults.editors.purlString = class purlString extends JSONEditor.defaults.editors.string {

    build() {
        super.build();
        this.purlHint = document.createElement('div');
        this.purlHint.className = 'lbl purl-hint';
        this.control.appendChild(this.purlHint);
        // The legacy editors are created after this one - they are not in
        // defaultProperties, so setValue appends them - and the user can edit
        // them once they exist. Neither notifies this editor, so watch them.
        this.legacyWatchListener = () => this.refreshPurlHint();
        this.legacyWatchPaths = ['collectionURL', 'packageName']
            .map((key) => this.parent.path + '.' + key);
        this.legacyWatchPaths.forEach(
            (path) => this.jsoneditor.watch(path, this.legacyWatchListener));
        this.refreshPurlHint();
    }

    destroy() {
        this.legacyWatchPaths.forEach(
            (path) => this.jsoneditor.unwatch(path, this.legacyWatchListener));
        super.destroy();
    }

    onChange(bubble, fromTemplate) {
        super.onChange(bubble, fromTemplate);
        // Covers the programmatic paths too - load, import, draft restore,
        // realtime - so the hint always matches the committed value.
        this.refreshPurlHint();
    }

    // True when the record already carries a legacy identifier.
    hasLegacyIdentifiers() {
        const editors = this.parent && this.parent.editors;
        if (!editors) {
            return false;
        }
        return ['collectionURL', 'packageName'].some((key) => {
            const editor = editors[key];
            return !!(editor && String(editor.getValue() || '').trim());
        });
    }

    refreshPurlHint(rawValue) {
        if (!this.purlHint) {
            return;
        }
        const derived = this.hasLegacyIdentifiers() ? null : purlToLegacyIdentifiers(
            rawValue === undefined ? this.getValue() : rawValue);
        this.purlHint.textContent = derived
            ? 'Legacy identifiers, added when this record is published \u2014 '
                + 'collectionURL: ' + derived.collectionURL
                + ' \u00b7 packageName: ' + derived.packageName
            : '';
    }
};

JSONEditor.defaults.resolvers.unshift(function (schema) {
    if (schema.type === "string" && schema.options && schema.options.purlAutofill) {
        return "purlString";
    }
});
