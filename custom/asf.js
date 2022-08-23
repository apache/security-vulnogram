const { v4: uuidv4 } = require('uuid');
const request = require('request');
const express = require('express');
const conf = require('../config/conf');
const email = require('../customRoutes/email.js');

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
    admin = '';
    if (user.group) {
        admin = user.group.includes(conf.admingroupname)
    }
    res.render('users/view', {
        title: 'Profile: ' + user.username,
        profile: user,
        admin: admin,
        page: 'users',
    });
}

function userslist (req,res) {
    res.render('blank');
}

function cvenew (req,res,next) {
    var pmcs = req.user.pmcs;
//    if (pmcs.includes(conf.admingroupname)) {
//        next();
//    } else {
	res.redirect("/allocatecve");
//    }
}

// If we are in security team then allow you to assign the CVE to any PMC
// otherwise give a radio list of the PMCs you are part of

function userslistjson (req, res) {
    if (req.isAuthenticated()) {
	groups = req.user.pmcs;

	if (groups && groups.includes(conf.admingroupname)) {
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
    },
    asfroutes: function (ensureAuthenticated, app) {
        app.use('/.well-known', express.static("/opt/cveprocess/.well-known", { dotfiles: 'allow' } ));
        let ac = require('../customRoutes/allocatecve');
        app.use('/allocatecve', ensureAuthenticated, ac.protected);
        let semail = require('../customRoutes/sendemails');
        app.use('/sendemails', ensureAuthenticated, semail.protected);
        app.get('/users/setpmc', ensureAuthenticated, setpmc);
        app.get('/users/me/json', ensureAuthenticated, usersmejson);
        app.get('/users/list/json', ensureAuthenticated, userslistjson); // replaces existing
        app.get('/users/list/', ensureAuthenticated, userslist); // replaces existing
        app.get('/users/profile/:id(' + conf.usernameRegex + ')?', ensureAuthenticated, usersprofile); // replaces existing
    },
}
