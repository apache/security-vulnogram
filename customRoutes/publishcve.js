const express = require('express');
const protected = express.Router();
const conf = require('../config/conf');
const csurf = require('csurf');
var request = require('request');
const email = require('./email.js');
const asf =  require('../custom/asf.js');
var csrfProtection = csurf();
var textUtil = require('../public/js/util.js');

// We have to duplicate this from custom/cve5/asfpreload.js
global.getProductListNoVendor = function getProductListNoVendor(c) {
    var lines = [];
    for (var affected of c.containers.cna.affected) {
        lines.push(affected.product);
    }
    return lines.join(", ");
}

// Is the PMC allowed to do a live CVE.org push?
// Currently only if you are in security group or if you're listed in the config,
// or if the config allows all (*) but you're not listed as an exception

function allowedtopushlive(pmcsiamin, specificpmc) {
    if (pmcsiamin.includes(conf.admingroupname)) {
        return true;
    }
    if (!pmcsiamin.includes(specificpmc)) {
        return false; // they're messing with the form
    }
    return false;
    // This isn't implemented yet
    //
    if (conf.pmcstrustedascna.includes("*")) {
        if (conf.pmcstrustedascna.includes("-"+specificpmc)) {
            return false;
        }        
        return true;
    }    
    if (conf.pmcstrustedascna.includes(specificpmc)) {
        return true;
    }
    return false;
}


protected.post('/', csrfProtection, async function(req,res) {
    var q = {};
    var opts = {"idpath":"body.cveMetadata.cveId"};
    console.log("publishcve", req.body.cve);
    q[opts.idpath] = req.body.cve;
    let Document = res.locals.docs.cve5.Document;
    var doc = await Document.findOne(q);
    if (!doc) {
        res.json({"body": req.body.cve+" not found"});
        res.end();
        return;
    }

    // We now have a loaded document for the given CVE ID
    
    var cvepmcowner  = doc.body.CNA_private.owner;
    if (!allowedtopushlive(req.user.pmcs,cvepmcowner)) {
        res.json({"body":"Sorry the PMC "+cvepmcowner+" has no push rights"});
        res.end();    
        return true;        
    }

    // We now know that the user trying to push it is allowed to do so
    j = textUtil.reduceJSON(doc.body);

    // We now have the document the same as the CVE-JSON tab had
    
    res.json({"body":"Push is authorised for you, but not yet implemented. ("+req.body.cve+" "+doc.body.CNA_private.state+")"});
    res.end();    
    return true;
});

module.exports = {
    protected: protected
};
