const { v4: uuidv4 } = require('uuid');
const request = require('request');
const express = require('express');
const conf = require('../config/conf');

// If you are in security pmc allow you to specify a different pmc for testing

function setpmc(req, res) {
    if (req.isAuthenticated()) {
	groups = req.user.pmcs;
	if (groups.includes(conf.admingroupname)) {
	    if (req.query.pmc) {
		req.session.user.pmcs = req.query.pmc.split(',');
		res.json({"result":"ok"});
	    } else {
		res.json({"error":"no pmc given"});
	    }
	} else {
            res.json({"error":"you are not in "+conf.admingroupname+" pmc"});
	}
    }
}

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

function usersmejson (req, res) {
    if (req.isAuthenticated()) {
	groups = req.user.pmcs;
        res.json({
            default: req.user.email,
            value: req.user.email,		    
	});
    }
}

function usersprofile (req,res) {
    user = req.user;
    user.group = user.pmcs;
    res.render('users/view', {
        title: 'Profile: ' + user.username,
        profile: user,
        admin: 	user.group.includes(conf.admingroupname),
        page: 'users',
    });
}

function userslist (req,res) {
    res.render('blank');    
}

// If we are in security team then allow you to assign the CVE to any PMC
// otherwise give a radio list of the PMCs you are part of

function userslistjson (req, res) {
    if (req.isAuthenticated()) {
	groups = req.user.pmcs;

	if (groups.includes(conf.admingroupname)) {
            res.json({
		"description": "lower case pmc name to assign this to",
		"options": {"grid_columns":12},
	    });
	} else {
            res.json({
		enum: groups,
		format: "radio",
		options: {enum_titles: groups},
	    });
	}
    }
}

var self = module.exports = {
    asfinit: function (app) {
        app.use(function (req, res, next) {
            if (req.session.user && req.session.user.username) {
	        req.user = req.session.user
            }
            res.locals.docs = app.locals.docs;
            next();
        });
    },

    asfgroupacls: function (documentacl,yourpmcs) {
	//console.log('mjc9 doc owner is '+documentacl+" and you are "+yourpmcs);
	if (yourpmcs.includes(conf.admingroupname)) {
	    return true;
	}
	for (i=0; i< yourpmcs.length; i++) {
	    if (yourpmcs[i] == documentacl) {
		return true;
	    }
	}
	//console.log('mjc9 access denied');
	return false;
    },
    
    asfroutes: function (ensureAuthenticated, app) {
        app.get("/users/login", asflogin); // replaces existing
        app.use('/.well-known', express.static("/home/mjc/server/.well-known", { dotfiles: 'allow' } ));
        let ac = require('../customRoutes/allocatecve');
        app.use('/allocatecve', ensureAuthenticated, ac.protected);
        app.get('/users/setpmc', ensureAuthenticated, setpmc);
        app.get('/users/me/json', ensureAuthenticated, usersmejson); 
        app.get('/users/list/json', ensureAuthenticated, userslistjson); // replaces existing
        app.get('/users/list/', ensureAuthenticated, userslist); // replaces existing        
        app.get('/users/profile/:id(' + conf.usernameRegex + ')?', ensureAuthenticated, usersprofile); // replaces existing        
    },
    
}
