const express = require('express');
const protected = express.Router();
const conf = require('../config/conf');
const csurf = require('csurf');
var request = require('request');
const email = require('./email.js');
const doc = require('../routes/doc.js');
const optSet = require('../models/set');

var csrfProtection = csurf();

protected.get('/test', csrfProtection, function(req,res) {
    console.log(JSON.stringify(res.locals));
    res.redirect('/cve');
});

protected.get('/', csrfProtection, function (req, res) {
    thisyear = new Date().getFullYear();
    res.render('../customRoutes/allocatecve', {
        title: 'Reserve and Allocate CVE.  Will get IDs from Mitre, create template documents, and send an email',
        number: 1,
	title: '',
        year: thisyear,
        csrfToken: req.csrfToken()
    });
});

// number, year, pmc, email
protected.post('/', csrfProtection, async function(req,res) {
    if (!res.locals.docs) {
        console.log(res.locals);
        return;
    }
    
    let Document = res.locals.docs.cve.Document;
    let html = "";

    groups = req.user.pmcs;
    if (!groups.includes(conf.admingroupname)) {
        req.flash('error',"not allowed");
        res.render('blank');
        return;
    }
    
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
                    cve = body.cve_ids[cveid].cve_id;
                    console.log("got a CVE ID "+cve+" reserved for "+req.body.pmc+" for "+req.body.email);
		    se = email.sendemail({"to":"mjc@apache.org",
                                          "cc":req.body.email,
					  "subject":cve+" reserved for "+req.body.pmc,
					  "text":"description: "+req.body.cvetitle+"\n\n"}).then( (x) => {  console.log("sent CVE notification mail "+x);});

		    // probably some better way of doing this for sure; we could render the schema i suppose?
		    newdoc = { "data_type" : "CVE", "data_format" : "MITRE", "data_version" : "4.0", "generator" : { "engine" : "Vulnogram 0.0.9" }, "CVE_data_meta" : { "ID" : cve, "ASSIGNER" : "security@apache.org", "DATE_PUBLIC" : "", "TITLE" : req.body.cvetitle, "AKA" : "", "STATE" : "RESERVED" }, "source" : { "defect" : [ ], "advisory" : "", "discovery" : "UNKNOWN" }, "affects" : { "vendor" : { "vendor_data" : [ { "vendor_name" : "Apache Software Foundation", "product" : { "product_data" : [ { "product_name" : "", "version" : { "version_data" : [ { "version_name" : "", "version_affected" : "", "version_value" : "", "platform" : "" } ] } } ] } } ] } }, "problemtype" : { "problemtype_data" : [ { "description" : [ { "lang" : "eng", "value" : "" } ] } ] }, "description" : { "description_data" : [ { "value" : "", "lang" : "eng" } ] }, "references" : { "reference_data" : [ { "refsource" : "CONFIRM", "url" : "", "name" : "" } ] }, "configuration" : [ ], "exploit" : [ ], "work_around" : [ ], "solution" : [ ], "credit" : [ ], "CNA_private" : { "owner" : req.body.pmc, "publish" : { "ym" : "", "year" : "", "month" : "" }, "share_with_CVE" : true, "CVE_table_description" : [ ], "CVE_list" : [ ], "internal_comments" : "", "todo" : [ ], "email" : req.body.email } };

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
                            res.write( "<p><a href=\"/cve/"+cve.slice()+"\">"+cve.slice()+"</a>");
			}
		    });
                }
            }
        }
    });
});


module.exports = {
    protected: protected
};
