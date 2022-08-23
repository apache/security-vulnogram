module.exports = {
    conf: {
        shortcuts: ["","",""],
    },
    facet: {
        ID: { showDistinct: false },
        CVSS: { hideColumn: true },
        Advisory: { hideColumn: true },
        product: { chart: false },
        ym: { chart: false },
        owner: {bulk: false, class: '',enum: '' },
        state: {bulk:false },
        severity: {chart: false},
        date: {hideColumn: true},
        discovery: {chart: false, hideColumn: true},
        Defect: {hideColumn: true},
    },
    schema: {
        "properties": {
            "cveMetadata": {
                "cveId": { },
            },
            "CNA_private": {
                "properties": {
                    "owner": {
                        "title": "Apache PMC",
                        "format": "",
                    },
                    "todo": {
                        "options": {
			    "hidden": "true"
                        }
                    },
                    "type": {
                        "options": {
			    "hidden": "true"
                        }
                    }                    
                }
            },
            "containers": {
                "properties": {                
                    "cna": {
                        "properties": {
                            "providerMetadata": { },
                            "title": { },
                            "datePublic": { },
                            "problemTypes": { },
                            "impacts": { },
                            "source": {},
                            "affected": { },
                            "descriptions": { },
                            "references": { } ,
                            "metrics": { },
                            "configurations": { },
	                    "workarounds": {
		                "items": {
                                    "title": "Mitigation/Work Around (optional, not sent to Mitre)",
                                },                
	                    },
                            "solutions": {},
                            "exploits": {
                                "options": {
			            "hidden": "true"
                                }
                            },
                            "timeline": {},
                            "credits": {},
                            "tags": {
                                "options": {
			            "hidden": "true"
                                }
                            },
                            "taxonomyMappings": {
                                "options": {
			            "hidden": "true"
                                }
                            },
                            "x_generator": {},
                        }
                    },
                    "adp": {
                        "options": {
			    "hidden": "true"
		        }
                    }
                }
            }
        }
    },
    script: {
        testscript: function(cve) {
            console.log(cve);
        }
    }
}
