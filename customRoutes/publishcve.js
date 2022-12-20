const express = require('express');
const protected = express.Router();
const conf = require('../config/conf');
const csurf = require('csurf');
var request = require('request');
const email = require('./email.js');
//const doc = require('../routes/doc.js');
//const optSet = require('../models/set');

var csrfProtection = csurf();

protected.post('/', csrfProtection, async function(req,res) {
    console.log("publishcve", req.body);    
    res.json({"body":"Push is not yet implemented. ("+req.body.cve+")"});
    res.end();    
    return true;
});

module.exports = {
    protected: protected
};
