const express = require('express');
const protected = express.Router();
const conf = require('../config/conf');
const csurf = require('csurf');
var request = require('request');
const email = require('./email.js');
const doc = require('../routes/doc.js');
const asf =  require('../custom/asf.js');
const optSet = require('../models/set');

var csrfProtection = csurf();

// Is the PMC allowed to do a live Mitre allocation?
// Currently only if you are in security group

function allowedtoallocatelive(pmcsiamin, specificpmc) {
    if (pmcsiamin.includes(conf.admingroupname)) {
        return true;
    }
    if (!pmcsiamin.includes(specificpmc)) {
        return false; // they're messing with the form
    }
    if (conf.pmcstrustedascna.includes(specificpmc)) {
        return true;
    }
    return false;
}

// use 'number: 1' below if you want to allow more than one CVE to get alocated at once. probably not
// very useful/likely even though we do support it

// use 'year: thisyear' below if you want to allow the year to be specified.  This is really only useful
// perhaps at the end of the year when you know something isn't public until the next year, but really this
// isn't important.


protected.get('/', csrfProtection, function (req, res) {
    thisyear = new Date().getFullYear();
    var title = "This form will request a CVE direct from the CVE project.  It will create a new CVE document here and send an email with the CVE name to the security team and the PMC.";
    if (req.user.pmcs.length == 1) {
        if (!allowedtoallocatelive(req.user.pmcs,req.user.pmcs[0])) {
            title = "This form will request a CVE from the ASF Security team by email.";
        }
    } else if (!req.user.pmcs.includes(conf.admingroupname)) {
        title = "This form will request a CVE either from the ASF Security team, or if your PMC is allowed, direct from the CVE project.  In either case an email will be sent to the security team and the PMC.";
    }
    res.render('../customRoutes/allocatecve', {
        title: title,
//        number: 1,
	cvetitle: "",
//        year: thisyear,
        csrfToken: req.csrfToken()
    });
});

// number, year, pm
protected.post('/', csrfProtection, async function(req,res) {
    if (!res.locals.docs) {
        console.log(res.locals);
        return;
    }
    var testmode =!conf.cveapiliveservice;
    var pmc = req.body.pmc.toLowerCase();

    var eto = asf.getsecurityemailaddress(pmc);
    if (pmc =="security" || testmode) {
        eto = "security@apache.org";
    }
    
    let Document = res.locals.docs.cve.Document;
    let html = "";

    if (!req.body.number) {
        req.body.number = 1;
    }
    if (!req.body.year) {
        req.body.year = new Date().getFullYear();
    }
    if (!req.body.cvetitle || req.body.cvetitle == "") {
        req.flash('error',"description can not be blank");
        res.render('blank');
        return;
    }
    
    if (!allowedtoallocatelive(req.user.pmcs,pmc)) {

        // Not allowed to allocate a CVE live, but requests one from security@

        var s2 = email.sendemail({"to":"security@apache.org",
                                  "cc":eto,
                                  "subject":"CVE request for "+pmc,
                                  "text":"requestor: "+req.user.username+"\npmc: "+pmc+"\n\n"+req.body.cvetitle,
                                 }).then( (x) => {  console.log("sent CVE request mail "+x);});
        
        req.flash('success',"An email has been sent to security@apache.org requesting the CVE name");
        res.render('blank');
        return;
    }
    console.log("Requesting "+req.body.number+" "+ req.body.year + " CVE for "+req.body.pmc)
    
    var opt = {
        'method' : 'POST',
        'url': conf.cveapiurl+'?amount='+req.body.number+'&cve_year='+req.body.year+'&short_name='+conf.cveapishortname+'&batch_type=sequential',
        'json': true,
        'headers': conf.cveapiheaders,
    };
    await request(opt, async function (error, response, body) {
//        body = {"cve_ids":[{"requested_by":{"cna":"address","user":"joshuaburton@address.com"},"cve_id":"CVE-2021-20252","cve_year":"2021","state":"RESERVED","owning_cna":"address","reserved":"2020-10-26T17:20:04.291Z"},{"requested_by":{"cna":"address","user":"joshuaburton@address.com"},"cve_id":"CVE-2021-20253","cve_year":"2021","state":"RESERVED","owning_cna":"address","reserved":"2020-10-26T17:20:04.291Z"}]};
        if (error) {
            req.flash('error',error);
            res.render('blank');
        } else {
            if (body.error) {
                req.flash('error',"CVE service error '"+body.error+"': "+body.message);
                res.render('blank');
            } else {
                console.log("ok");
                var count = 0;
                for (cveid in body.cve_ids) {
                    cve = body.cve_ids[cveid].cve_id
                    if (testmode) {
                        cve = cve + "-TEST"
                    }
                    console.log("got a CVE ID "+cve+" reserved for "+pmc);
//		    var se = email.sendemail({"to":"mjc@apache.org",
//                                          "cc":req.body.email,
//					  "subject":cve+" reserved for "+pmc,
//					  "text":"description: "+req.body.cvetitle+"\n\n"}).then( (x) => {  console.log("sent CVE notification mail "+x);});

                    var beta = "Note that you should use our web based service to handle the process.  Please visit https://cveprocess.apache.org/cve/"+cve+" and note this it replaces the whole of section 16 of our requirements and full instructions are at that URL.\n\nThere is also a video tutorial available at https://s.apache.org/cveprocessvideo\n\n"
                    var pmctemplate = "Thank you for requesting a CVE name for your issue.  We suggest you copy and paste the name below as mistakes are easy to make and cumbersome to correct.\n\n"+cve+"\n"+req.body.cvetitle+"\n\n"+beta+"Note the process at https://www.apache.org/security/committers.html .\n\nIf you decide not to use the CVE name, or have any questions, please let us know asap.\n\nRegards, ASF Security Team"

		    var se2 = email.sendemail({"to":eto,
                                               "cc":"security@apache.org",
					       "subject":cve+" reserved for "+pmc,
					       "text":pmctemplate,
                                              }).then( (x) => {  console.log("sent CVE notification mail "+x);});
                    
		    // probably some better way of doing this for sure; we could render the schema i suppose?
		    newdoc = { "data_type" : "CVE",
                               "data_format" : "MITRE",
                               "data_version" : "4.0",
                               "generator" : {
                                   "engine" : "Vulnogram 0.0.9"
                               },
                               "CVE_data_meta" : {
                                   "ID" : cve,
                                   "ASSIGNER" : "security@apache.org",
                                   "DATE_PUBLIC" : "",
                                   "TITLE" : req.body.cvetitle,
                                   "AKA" : "",
                                   "STATE" : "RESERVED"
                               },
                               "source" : {
                                   "defect" : [ ],
                                   "advisory" : "",
                                   "discovery" : "UNKNOWN"
                               },
                               "affects" : {
                                   "vendor" : {
                                       "vendor_data" : [ {
                                           "vendor_name" : "Apache Software Foundation",
                                           "product" : {
                                               "product_data" : [ {
                                                   "product_name" : "",
                                                   "version" : {
                                                       "version_data" : [ {
                                                           "version_name" : "",
                                                           "version_affected" : "",
                                                           "version_value" : "",
                                                           "platform" : ""
                                                       } ]
                                                   }
                                               } ]
                                           }
                                       } ]
                                   }
                               },
                               "problemtype" : {
                                   "problemtype_data" : [ {
                                       "description" : [ {
                                           "lang" : "eng",
                                           "value" : ""
                                       } ]
                                   } ]
                               },
                               "description" : {
                                   "description_data" : [ {
                                       "value" : "",
                                       "lang" : "eng"
                                   } ]
                               }, "references" : {
                                   "reference_data" : [ {
                                       "refsource" : "CONFIRM",
                                       "url" : "",
                                       "name" : ""
                                   } ]
                               },
                               "configuration" : [ ],
                               "exploit" : [ ],
                               "work_around" : [ ],
                               "solution" : [ ],
                               "credit" : [ ],
                               "CNA_private" : {
                                   "owner" : pmc,
                                   "publish" : {
                                       "ym" : "",
                                       "year" : "",
                                       "month" : ""
                                   },
                                   "share_with_CVE" : true,
                                   "CVE_table_description" : [ ],
                                   "CVE_list" : [ ],
                                   "internal_comments" : "",
                                   "todo" : [ ],
                                   "email" : "",
                               }
                             };

		    let entry = new Document({
			"body": newdoc,
			"author": req.user.username
		    });
		    await entry.save(function (err, doc) {
			if (err || !doc._id) {
			    req.flash('error',JSON.stringify(err));
			} else {
			    console.log(err,doc);
                            count++;
                            //res.redirect('/cve/' + cve.slice());
                            //res.write( "<p><a href=\"/cve/"+cve.slice()+"\">"+cve.slice()+"</a>");
			}
		    });
                }
                for (cveid in body.cve_ids) {
                    cve = body.cve_ids[cveid].cve_id
                    res.write( "<p><a href=\"/cve/"+cve.slice()+"\">"+cve.slice()+"</a>");
                }
                res.end();
            }
        }
    });
});


module.exports = {
    protected: protected
};
