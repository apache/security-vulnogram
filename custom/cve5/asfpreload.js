function getProductListNoVendor(cve) {
    var lines = [];
    for (var affected of cve.containers.cna.affected) {
        lines.push(affected.product);
    }
    return lines.join(", ");
}

async function loadProductNames() {
    var projects = []
    try {
	var pmcs = userPMCS.split(',');
	var response = await fetch('https://whimsy.apache.org/public/committee-info.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error'
	});
	if (!response.ok) {
	    errMsg.textContent = "Failed Apache project list";
	    infoMsg.textContent = "";
	    throw Error(id + ' ' + response.statusText);
	} else {
	    var res = await response.json();
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
    return (projects);
}



async function loadProjectUrl(pmc) {
    var url = ""
    try {
	var response = await fetch('https://whimsy.apache.org/public/committee-info.json', {
	    method: 'GET',
	    credentials: 'omit',
	    headers: {
		'Accept': 'application/json, text/plain, */*'
	    },
	    redirect: 'error'
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
