module.exports = {
    schema: {
	"definitions": {
	    "cve_id": {
		"links": ["", ""]
	    },
	    "product": {
		"properties": {
		    "product_name": {
			"description": "e.g. Apache Tomcat",

			//            "examples": ["Apache Tomcat"]
			//"$ref":"URL of json document with product names"
		    },
		    "version": {
			"properties": {
			    "version_data": {
				"items": {
				    "properties": {
					"version_name": {
					    "description": "e.g. Apache Tomcat 9",
					},
					"version_value": {
					    "description": "e.g. 9.0.0.M1 to 9.0.0.M17",
					},
					"platform": {
					    "description": "e.g. Windows (optional)",
					}
				    }
				}
			    }
			}
		    }
		}
	    }
	},
	"properties": {
	    "CVE_data_meta": {
		"properties": {
		    "ID": {
			"description":"CVE-yyyy-nnnnn as allocated to you by ASF Security",
			"options":{			
			    "grid_columns":12,
			},
		    },
		    "ASSIGNER": {
			"default": "security@apache.org",
			"options": {
			    "hidden": "true"
			}
		    },
		    "TITLE": {
			"description": "e.g. Apache Tomcat HTTP/2 denial of service (optional, this is not used for the Mitre entry)"
		    },
		    "AKA": {
			"description": "e.g. HeartBleed (optional, only use for specifically branded issues, this is not used for the Mitre entry)",
			"options": {
			    "grid_columns":12
			},
		    },    
		    "STATE": {
			"type": "string",
			"description": "Use DRAFT when you are working on the advisory, move to REVIEW to have ASF security review",
			"default": "RESERVED",
			"enum": [
			    "RESERVED",
			    "DRAFT",
			    "REVIEW",
			    "READY",
			    "PUBLIC"],
			"format": "radio",
			"options": {
			    "grid_columns":12
			}
		    },
                    "DATE_PUBLIC": {
			"description": "The date this issue was public or blank or a future date is not public yet",
			"options": {
			    "grid_columns": 12
			},
		    },		    
		}
	    },
	    "source": {
		"properties": {
		    "defect": {
			"description": "Project specific bug ids e.g. TOMCAT-522 (optional, this is not used for the Mitre entry)"
		    },
		    "advisory": {
			"description": "Project specific advisory id e.g. TOMCAT-2019-12 (optional, this is not used for the Mitre entry)",
		    },
		    "discovery": {
			"default": "UNKNOWN",
			"options": {
			    "hidden": "true"			    
			},
		    }
		}
	    },
	    "affects": {
		"properties": {
		    "vendor": {
			"title": "vendor: Apache Software Foundation",
			"properties": {
			    "vendor_data": {
				"items": {
				    "properties": {
					"vendor_name": {
					    "default": "Apache Software Foundation",
					    "options": {
						"hidden": "true",
					    }
					}
				    }
				}
			    }
			}
		    }
		}
	    },
	    "references": {
		"properties": {
		    "reference_data": {
			"items": {
			    "properties": {
				"refsource": {
				    "title": "refsource: (use 'CONFIRM' type for links to official ASF resources)"
				},
				"url": {
				    "description": "e.g. link at an apache site or permalink to a lists.apache.org mailing list post"
				},
				"name": {
				    "description": "usually these are blank or the same as the url for Mitre",
				    "options": {
					"hidden": "true",
				    }
				}
			    }
			}
		    }
		}
	    },
	    "configuration": {
		"options": {
		    "hidden": "true"
		},
	    },
	    "exploit": {
		"options": {
		    "hidden": "true"
		},
	    },
	    "work_around": {
		"options": {
		    "hidden": "true"
		},
	    },
	    "solution": {
		"options": {
		    "hidden": "true"
		},
	    },
	    "impact": {
		"type": "object",
		"options": {
		    "hidden": "true"
		},
		"properties": ""
	    },
	    "description": {
		"title":"test",
		"properties": {
		    "description_data": {
			"items": {
			    "title": "another description section",
			    "properties": {
				"value": {
				    "title": "description: (due to an unfixed bug please click in the 1px high box below and press a key) **Note that Mitre request that we please include the product and version information in the description itself as well as in the version section line in our submissions**)",
				    "description": "e.g. While investigating bug 60718, it was noticed that some calls to application listeners in Apache Tomcat versions 9.0.0.M1 to 9.0.0.M17, 8.5.0 to 8.5.11, 8.0.0.RC1 to 8.0.41 and 7.0.0 to 7.0.75 did not use the appropriate facade object. When running an untrusted application under a SecurityManager, it was therefore possible for that untrusted application to retain a reference to the request or response object and thereby access and/or modify information associated with another web application.",
				}
			    }
			}
		    }
		}
	    },
	    "credit": {
		"items": {
                    "title": "credit statement (optional)",
		    "properties": {
			"value": {
			    "description": "Apache Tomcat would like to thank B Lobby for reporting this issue.",
			}
		    }
		}
	    },
	    "CNA_private": {
		"properties": {
		    "owner": {
			"title": "Apache PMC",
		    },
                    "email" : {
			"type":"string",
			"description":"your apache email address",
			"title":"ASF Email Address",
			"$ref": "/users/me/json",			
			"options":{
			    "hidden":false,
			    "grid_columns":12,
			},
		    },
		    
		    "share_with_CVE": {
			"default": "false",
			"value": "false",
			"options": {
			    "hidden": true
			},	

		    },
		"CVE_table_description": {
		    "title": "test",
		    "options": {
			"hidden": true
		    },				    
		},
		"CVE_list": {
		    "options": {
			"hidden": true
		    },
		},
		"internal_comments": {
		    "options": {
			"hidden": true
		    },
		},
		"todo": {
		    "options": {
			"hidden": true
		    },
		    
		},
	    },
	    },
	},
    },
    script: {
        getProductListNoVendor: function (cve) {
            var lines = [];
            for (var vendor of cve.affects.vendor.vendor_data) {
                var pstring = [];
                for (var product of vendor.product.product_data) {
                    pstring.push(product.product_name);
                }
                lines.push(pstring.join(", "));
            }
            return lines.join("; ");
        },

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