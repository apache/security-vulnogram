const { v4: uuidv4 } = require('uuid');
const request = require('request');
const express = require('express');

function asflogin (req, res) {
    sess = req.session;
    if (req.query.code) {
	const userinfo_endpoint= 'https://oauth.apache.org/token'
	uri = userinfo_endpoint+"?code="+req.query.code
	request(uri, {json:true},(err,cbres,body) => {
	    if (err) {res.send(err);}
	    else if (cbres.statusCode != 200) {res.send(body);}
	    else if (body.state != sess.state) { res.send("auth is broken") }
	    else {
		sess.user = {username:body.uid, email:body.email, name:body.fullname, pmcs:body.pmcs};
		//sess.user = {username:body.uid, email:body.email, name:body.fullname, pmcs:["airflow"]};		
		if (sess.returnTo) {
		    res.redirect(req.session.returnTo);
		    delete req.session.returnTo;
		} else {
		    res.redirect("/");
		}
		console.log(body);
	    }
	});
    } else {
	delete  sess.user;
	sess.state = uuidv4();
	const authorization_endpoint= 'https://oauth.apache.org/auth'
	redirecturl = authorization_endpoint+"?state="+sess.state+"&redirect_uri=https://"+req.get('host')+req.originalUrl;
	res.redirect(redirecturl)
    }
}


var self = module.exports = {
    asfinit: function (app) {
        app.use(function (req, res, next) {
            if (req.session.user && req.session.user.username) {
	        req.user = req.session.user
            }        
            next();
        });
    },

    asfroutes: function (ensureAuthenticated, app) {
        app.get("/users/login", function (req, res) { return asflogin(req,res) });
        app.use('/.well-known', express.static("/home/mjc/server/.well-known", { dotfiles: 'allow' } ));
        let ac = require('../customRoutes/allocatecve');
        app.use('/allocatecve', ensureAuthenticated, ac.protected);
    },
    
}
