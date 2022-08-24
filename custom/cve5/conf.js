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
                            "title": {
                                "options": {
                                    "inputAttributes": {
                                        "placeholder": "e.g. Apache Tomcat HTTP/2 denial of service (this is used for email subject)"
                                    }
                                }
                            },
                            "datePublic": {
                                "options": {
                                    "hidden": "true"
                                }                                
                            },
                            "problemTypes": { },
                            "impacts": {
                                "options": {
                                    "hidden": "true"
                                }
                            },
                            "source": {},
                            "affected": { },
                            "descriptions": {
				"title": "CVE Description: Please also include the product and version information in the description itself",       
                                "items": {
                                    "description": {
                                        "title": "test1",
                                    },
                                    "options": {
                                        "inputAttributes": {
                                            "placeholder": "e.g. Apache Tomcat HTTP/2 denial of service (this is used for email subject)"
                                        }                                        ,
                                    },
			            "properties": {
				        "value": {
				            "title": "description: Note that Mitre request that we please include the product and version information in the description itself as well as in the version section line in our submissions)",
				            "description": "e.g. While investigating bug 60718, it was noticed that some calls to application listeners in Apache Tomcat versions 9.0.0.M1 to 9.0.0.M17, 8.5.0 to 8.5.11, 8.0.0.RC1 to 8.0.41 and 7.0.0 to 7.0.75 did not use the appropriate facade object. When running an untrusted application under a SecurityManager, it was therefore possible for that untrusted application to retain a reference to the request or response object and thereby access and/or modify information associated with another web application.",
                                    "options": {
                                        "inputAttributes": {
                                            "placeholder": "e.g. Apache Tomcat HTTP/2 denial of service (this is used for email subject)"
                                        }                                        ,
                                    },
                                            
                                        }
                                    }
                                }
                            },
                            "references": {
                                "title" : "references: use 'vendor-advisory' tag for pointer to ASF mailing list announcement",
                                "options": {
                                        "infoText": "test"
                                }
                            } ,
                            "metrics": {
                                "items": {
                                    "required": ["other"],
                                    "title": "Other" 
                                }
                            },
                            "configurations": { },
	                    "workarounds": {
		                "items": {
                                    "title": "Mitigation/Work Around (optional)",
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
