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
        state: { path: 'body.CNA_private.state',
                 bulk: false,
                 "enum": [
                     "RESERVED",
                     "DRAFT",
                     "REVIEW",
                     "READY",                            
                     "CLOSED",
                 ],
                 icons: {
                     RESERVED: 'inbox',
                     DRAFT: 'edit',
                     REVIEW: 'eye',
                     READY: 'wait',
                     CLOSED: 'closed'
                 }
               },
        type: {hideColumn: true, bulk: false, tabs: false},
        cveState: {hideColumn: true, tabs: false},
        cvss: {hideColumn: true},
        defect: { hideColumn: true},
        date: { hideColumn: true},        
        severity: {chart: false},
        date: {hideColumn: true, bulk: false},
        discovery: {chart: false, hideColumn: true, bulk: false},
        Defect: {hideColumn: true},
    },
    schema: {
        "definitions": {
            "CNA_private": {
                "properties": {
                    "state": {
                        "enum": [
                            "RESERVED",
                            "DRAFT",
                            "REVIEW",
                            "READY",                            
                            "CLOSED",
                        ],
                    }
                }
            },
            "cveId" : {
                "options": {
                    "inputAttributes": {
                        "placeholder": "CVE-yyyy-nnnnn as allocated to you by ASF Security",
                    },
                }
            }
        },
        
        "title":" ",
        "properties": {
            "cveMetadata": {
                "cveId": { },
                "properties": {
                    "cveId": {
                        "links": [],
                    },
                }
            },
            "CNA_private": {
                title: " ",
                "properties": {
                    "userslist": {
                        "options": {
                            "hidden": "true"
                        }
                    },
                    "owner": {
                        "title": "Apache PMC",
                        "format": "",
                    },
                    "state": {
                        "enum": [
                            "RESERVED",
                            "DRAFT",
                            "REVIEW",
                            "READY",                            
                            "CLOSED",
                        ],
                        icons: {
                            RESERVED: 'inbox',
                            DRAFT: 'edit',
                            REVIEW: 'eye',
                            READY: 'cal',
                            CLOSED: 'closed'
                        }        ,                
                        "default": "RESERVED",
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
                            "source": {
                                "properties": {
		                    "defect": {
                                        "options": {
                                            "grid_columns": 8,
                                            "inputAttributes": {
			                        "placeholder": "Project specific bug ids e.g. TOMCAT-522 (optional, this is not used for the Mitre entry)"
                                            }
                                        }
                                    },
                                    "advisory": {
                                        "options": {
                                            "inputAttributes": {
			                        "placeholder": "Project specific advisory id e.g. TOMCAT-2019-12 (optional, this is not used for the Mitre entry)",
                                            }
                                        }
		                    },
                                    "discovery": {
                                        "title": "Source of vulnerability discovery (optional)",
		                    },                                    
                                }
                            },
                            "affected": {
                                "items":{
		                    "properties": {
		                        "vendor": {
			                    "title": "vendor: Apache Software Foundation",
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "product": {
                                            "options": {
                                                "grid_columns": 8,
                                            }
                                        },
                                        "platforms": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "collectionURL": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "packageName": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "repo": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "modules": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "programFiles": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "programRoutines": {
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                    }
                                }
                            },
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
                                    "title": "Mitigation/Work Around",
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
            },
        }
    },
    script: {
        loadProductNames: async function () {
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
			for (var committee in res.committees) {
			    // or pmcs.includes('security') !
			    if (pmcs.includes(committee)) {
				res.committees[committee].display_name &&
				    projects.push('Apache ' + res.committees[committee].display_name);
			    }
			}
		    }
		}
	    } catch (error) {
		errMsg.textContent = error;
	    }
	    return (projects);
	}
    }
}
