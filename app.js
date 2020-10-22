// Copyright (c) 2017 Chandan B N. All rights reserved.

const express = require('express');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const https = require('https');


// ASF
const { v4: uuidv4 } = require('uuid');
const request = require('request');

// TODO: don't use express-session for large-scale production use
const session = require('express-session');

const passport = require('passport');
const crypto = require('crypto');
const compress = require('compression');
const conf = require('./config/conf');
const optSet = require('./models/set');

if(!process.env.NODE_ENV) {
    process.env.NODE_ENV = "production";
}

mongoose.Promise = global.Promise;
mongoose.connect(conf.database, {
    keepAlive: true,
    useNewUrlParser: true,
    useCreateIndex: true
});
const db = mongoose.connection;

//Check connection
db.once('open', function () {
    console.log('Connected to MongoDB');
});

//Check for db errors
db.on('error', function (err) {
   console.error(err.message);
   console.error('Check mongodb connection URL configuration. Ensure Mongodb server is running!');
   process.exit();
});

const app = express();

app.disable('x-powered-by');

// enable compression
app.use(compress());

app.set('env', 'production');
// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// make conf available for pug
app.locals.conf = conf;

// parse urlencoded forms
app.use(express.urlencoded({
    extended: true
}));

// parse application/json
app.use(express.json({limit:'16mb'}));

// serve files under public freely
app.use(express.static('public'));

// Express Session middleware
app.use(session({
    secret: crypto.randomBytes(64).toString('hex'),
    resave: true,
    saveUninitialized: false
}));

// Passport config
require('./config/passport')(passport);

app.use(passport.initialize());
app.use(passport.session());

// Express Messages Middleware
// This shows error messages on the client
app.use(require('connect-flash')());
app.use(function (req, res, next) {
    if (req.session.user && req.session.user.username) {
	req.user = req.session.user
    }
    res.locals.user = req.user || null;
    res.locals.startTime = Date.now();
    res.locals.messages = require('express-messages')(req, res);
    next();
});

// add this to route for authenticating before certain requests.
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        res.redirect('/users/login')
    }
}

//delete return redirect path
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    if (req.path != '/users/login' && req.session.returnTo) {
        delete req.session.returnTo
    }
    next()
})

app.get("/users/login", function (req, res) {
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
})

app.use('/.well-known', express.static("/home/mjc/server/.well-known", { dotfiles: 'allow' } ));

// set up routes
let users = require('./routes/users');
app.use('/users', users.public);
app.use('/users', ensureAuthenticated, users.protected);

let docs = require('./routes/doc');

app.locals.confOpts = {};

var defaultSections = fs.readdirSync('./default');
var customSections = fs.existsSync('./custom') ? fs.readdirSync('./custom') : [];
var sections = new Set([...defaultSections, ...customSections]);

for(section of sections) {
    var s = optSet(section, ['default', 'custom']);
    //var s = conf.sections[section];
    if(s.facet && s.facet.ID) {
        app.locals.confOpts[section] = s;
        let r = docs(section, app.locals.confOpts[section]);
        app.use('/' + section, ensureAuthenticated, r.router);
    }
}
delete app.locals.confOpts['nvd'];
delete app.locals.confOpts['home'];

app.use('/home/stats', ensureAuthenticated, async function(req, res, next){
    var sections = [];
    for(section of conf.sections){
        var s = {};
        try {
            var s = await db.collection(section+'s').stats();
        } catch (e){
            
        };
        if (s === {}) {
        try {
            var s = await db.collection(section).stats();
        } catch (e){
            
        };
        };
        
        sections.push({
            name: section,
            items: s.count,
            size: s.size,
            avgSize: s.avgObjSize
        });
    }
    res.render('list', {
        docs: sections,
        columns: ['name', 'items', 'size', 'avgSize'],
        fields: {
            'name': {
                className: 'icn'
            }
        }
    })
});

app.use(function (req, res, next) {
    res.locals.confOpts = app.locals.confOpts;
    next();
});

//Configuring a reviewToken in conf file allows sharing drafts with 'people who have a link containing the configurable token' 
let review = require('./routes/review');

if (review.public) {
    app.use('/review', express.static('public'));
    app.use('/review', review.public);
}

app.use('/review', ensureAuthenticated, review.protected);

if(conf.customRoutes) {
    for(r of conf.customRoutes) {
        app.use(r.path, require(r.route));
    }
}

app.get('/', function (req, res, next) {
    res.redirect(app.locals.confOpts['cve'].conf.uri);
});

if(conf.httpsOptions) {
    https.createServer(conf.httpsOptions, app).listen(conf.serverPort, conf.serverHost, function () {
        console.log('Server started at https://' + conf.serverHost + ':' + conf.serverPort);
    });
} else {
    app.listen(conf.serverPort, conf.serverHost, function () {
        console.log('Server started at http://' + conf.serverHost + ':' + conf.serverPort);
    });
}
