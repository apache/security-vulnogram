var conf = require('../../config/conf');
module.exports = {
    conf: {
        uri: '/cve5/?state=RESERVED,DRAFT,REVIEW,READY',        
        name: 'CVE 5.0',
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
                     "PUBLIC",
                 ],
                 icons: {
                     RESERVED: 'inbox',
                     DRAFT: 'edit',
                     REVIEW: 'eye',
                     READY: 'wait',
                     PUBLIC: 'closed'
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
                            "PUBLIC",
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
            },
            "orgId" : {
                "template": conf.cveorgid
            },
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
                    "emailed": {
                        "options": {
                            "hidden": "true"
                        }
                    },
                    "projecturl": {
                        "options": {
                            "hidden": "true"
                        }
                    },                                        
                    "owner": {
                        "title": "Apache PMC",
                        "format": "",
                    },
                    "userslist": {
                        "title": "This is your PMC list such as users@ or dev@ where you also want security announcement emails go to.  More than one list is okay, separate with commas",
                        "type": "string",
                        "options": {
                            "xhidden": "true"
                        }
                    },
                    
                    "state": {
                        "title": "State. Use DRAFT when you are working on the advisory. Move to READY when you want this published live and it will notify ASF Security. Set to REVIEW if you would like any help from ASF Security reviewing this entry.",
                        "enum": [
                            "RESERVED",
                            "DRAFT",
                            "REVIEW",
                            "READY",                            
                            "PUBLIC",
                        ],
                        icons: {
                            RESERVED: 'inbox',
                            DRAFT: 'edit',
                            REVIEW: 'eye',
                            READY: 'cal',
                            PUBLIC: 'closed'
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
                            "providerMetadata": {
                                "properties": {
                                    "orgId": {
                                        "template": conf.cveorgid
                                    },
                                }
                            },
                            "title": {
                                "title": "Title (Short issue description, also used in email subject lines)",
                                "options": {
                                    "inputAttributes": {
                                        "placeholder": "e.g. HTTP/2 denial of service (this is used for email subject)"
                                    }
                                }
                            },
                            "datePublic": {
                                "options": {
                                    "hidden": "true"
                                }                                
                            },
                            "problemTypes": {
                                "items": {
                                    "properties": {
                                        "descriptions": {
                                            "items": {
                                                "properties": {
                                                    "description": {
                                                        "options": {
                                                            "inputAttributes": {
                                                                "placeholder": "Vulnerability type: can be a pull-down CWE or free text"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "impacts": {
                                "options": {
                                    "hidden": "true"
                                },
                                "default": [],
                            },
                            "source": {
                                title: "ASF-specific details",
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
                                        "enum": [
                                            "INTERNAL", "EXTERNAL", "UNKNOWN"
                                        ],
                                        "options": {
                                            "enum_titles": [
                                                "internal", "external", "undefined"
                                            ]
                                        }
		                    },                                    
                                }
                            },
                            "affected": {
                                "items":{
		                    "properties": {
		                        "vendor": {
                                            "default": "Apache Software Foundation",
                                            "options": {
                                                "hidden": "true",
                                            }
                                        },
                                        "product": {
                                            "options": {
                                                "grid_columns": 8,
                                                "inputAttributes": {
                                                    "placeholder": "eg., Apache Tomcat"
                                                }
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
                                        "versions": {
                                            "items":{
		                                "properties": {
                                                    "status": { },
                                                    "version": { },
                                                    "lessThan": { },
                                                    "lessThanOrEqual": { },
                                                    "changes": {
                                                        "options": {
                                                            "hidden": "true",
                                                        }                                                        
                                                    },
                                                    "versionType": {
                                                       "default": "semver",
                                                    },
                                                },
                                            },
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
                                "title" : "References: use 'vendor-advisory' tag for pointer to ASF mailing list announcement once public",
                                "minItems": 0,
                            },
                            "metrics": {
                                "title":"Metrics. A text severity level is required (additional CVSS rating is optional)",
                                "items": {
                                    "properties": {
                                        "other": {
                                            "title": "Text version of Severity level",
                                            "properties": {
                                                "type" : {
                                                    "options": {
                                                        "hidden": "true",
                                                    }
                                                },
                                                "content": {
                                                    "title": " ",
                                                    "properties": {
                                                        "text": {
                                                            "title": " ",
                                                            "type": "string",
                                                            "default": "",
                                                            "examples": ["low","moderate","important","critical"],
                                                            "options": {
                                                                "inputAttributes": {
                                                                    "placeholder": "Use pulldown or free text"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                },
                                "default": [
                                    {
                                        "other": {
                                            "type": "Textual description of severity",
                                            "content": {
                                                "text":""
                                            }
                                        }
                                    }
                                ],
                            },
                            "configurations": {
                                "title":"Configurations required for exploiting this vulnerability (optional)",
                            },
	                    "workarounds": {
                                "title":"Workarounds and mitigations for this vulnerability (optional)",
		                "items": {
                                    "title": "Mitigation/Work Around",
                                },                
	                    },
                            "solutions": {
                                "title":"Information about solutions or remediations available (optional, such as 'upgrade to version 5')",
                                "options": {
			            "hidden": "true"
                                }                                
                            },
                            "exploits": {
                                "options": {
			            "hidden": "true"
                                }
                            },
                            "timeline": {},
                            "credits": {
                                "title": "Credits (optional, please use if externally reported issue)",
                            },
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
    validators: [
	conf.validators,
        function (schema, value, path) {
            var errors = [];
            if (path == 'root') {
                if (value && value.CNA_private && value.CNA_private.state && value.containers.cna.references) {
                    var asf = 0;
                    for (ref of value.containers.cna.references) {
                        if (ref.tags && ref.tags.includes("vendor-advisory") && ref.url && ref.url.includes("apache.org/")) {
                            asf+=1;
                        }
                    }
                    if (asf == 0 && value.CNA_private.state == 'PUBLIC') {
                        errors.push({path: path, property: 'format', message: 'In state PUBLIC you must include a vendor-advisory reference pointing to your advisory or mailing list post at an apache.org URL'});
                    }
                }
            } else if (path.startsWith('root.containers.cna.references')) {
                if (value.url != undefined) {
                    if (value.url.includes("dist.apache.org")) {
                        errors.push({path: "root.containers.cna.references", property: 'format', message: 'do not use dist.apache.org should be downloads.apache.org'});
                    }
                    if (value.tags && value.tags.includes("vendor-advisory") && !value.url.includes("apache.org/")) {
                        errors.push({path: "root.containers.cna.references", property: 'format', message: 'vendor-advisory tag must point to a URL at apache.org'});
                    }
                }
            } else if (path.startsWith('root.containers.cna.metrics') && path.endsWith(".other")) {
                if (!value.content) {
                    errors.push({path: path.replaceAll(".other", "") + ".oneOf[1].other.content.text", property: 'format', message: 'Severity level is required'});
                }
            }
            return errors;
        }
    ],
}
