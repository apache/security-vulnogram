const express = require('express');
const protected = express.Router();
const conf = require('../config/conf');
const csurf = require('csurf');
var request = require('request');
const email = require('./email.js');
const asf =  require('../custom/asf.js');
var csrfProtection = csurf();

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
    res.json({"body":"Push is not yet implemented. ("+req.body.cve+" "+doc.body.CNA_private.state+")"});
    res.end();    
    return true;
});

module.exports = {
    protected: protected
};
