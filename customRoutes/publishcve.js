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

function getCveIdState(cveid, cb) {
    var opt = {
        'method' : 'GET',
        'url': conf.cveapiurl+'/cve-id/'+ cveid,
        'json': true,
        'headers': conf.cveapiheaders,
    };
    try {
        request(opt, (error, response, body) => {
            if (error) {
                console.warn(error);
                cb("");
            } else {
                cb(body.state);
            }
        });
    } catch (error) {
        console.warn(error);
        cb("");
    }
}

function createCve(cveid, container, cb) {
    var opt = {
        'method' : 'POST',
        'url': conf.cveapiurl+'/cve/'+ cveid,
        'json': container,
        'headers': conf.cveapiheaders,
    };
    //console.log("createCve: ",cveid,container);
    try {
        request(opt, (error, response, body) => {
            //console.log("createCve: ",response, body);
            if (error) {
                console.warn(error);
                cb(error);
            } else if (body.error) {
                console.warn(error);
                cb(body.message);
            } else {
                cb();
            }
        });
    } catch (error) {
        console.warn(error);
        cb(error);
    }
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

    if (doc.body.CNA_private.state != "PUBLIC" && doc.body.CNA_private.state != "READY" ) {
        res.json({"body":req.body.cve+" is not in state PUBLIC or READY"});
        res.end();
        return true;
    }

    // We now have something we're allowed to push
    
    // portal.js does a getCveId(j.cveMetadata.cveId) and looks at the state so we know if
    // we're doing a first push or an update push

    var lateststate = await new Promise( res => { getCveIdState(req.body.cve, res)})
    //console.log("According to cve.org "+req.body.cve+" is state "+lateststate);
    
    if (lateststate == "RESERVED") {
        if (j.cveMetadata.state == "PUBLISHED") {
            var result = await new Promise( res => { createCve(j.cveMetadata.cveId, j.containers.cna, res)})
            if (!result) {
                res.json({"body":"Push to cve.org success."});
            } else {
                res.json({"body":"Push to cve.org failed. "+result});
            }
            res.end();    
            return true;            
        } else if (j.cveMetadata.state == "REJECTED") {
            res.json({"body":"Push is authorised for you, but 'reject new cve' not yet implemented."});
            res.end();    
            return true;                        
        }
    } else {
        if (j.cveMetadata.state == "PUBLISHED") {
            res.json({"body":"Push is authorised for you, but 'update public cve' not yet implemented."});
            res.end();    
            return true;                        
        } else if (j.cveMetadata.state == "REJECTED") {
            res.json({"body":"Push is authorised for you, but 'update rejected cve' not yet implemented."});
            res.end();    
            return true;                                    
        }
    }
    res.end();    
    return true;
});

module.exports = {
    protected: protected
};
