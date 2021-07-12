const fs = require("fs");
var package = require('../package.json');
var secrets = require('./secrets.js');

const privateKey = fs.readFileSync('/etc/letsencrypt/live/security-vm-he-fi.apache.org/privkey.pem', 'utf8');
const certificate = fs.readFileSync('/etc/letsencrypt/live/security-vm-he-fi.apache.org/cert.pem', 'utf8');
const ca = fs.readFileSync('/etc/letsencrypt/live/security-vm-he-fi.apache.org/chain.pem', 'utf8');

module.exports = {

    // CVE automation configuration and CNA name
    cveapiheaders: secrets.cveapiheaders,
    cveapiurl: "https://cveawg-dev.mitre.org/api/cve-id",
    cveapishortname: "night",
    cveapiliveservice: false,
    // which PMC is admin group?
    admingroupname: "security",

    // which PMC have a security@ address?
    pmcswithsecurityemails: ["commons","couchdb","dubbo","fineract","geronimo","guacamole","hadoop","hive","httpd","ignite","jackrabbit","kafka","libcloud","lucene","metron","milagro","nifi","ofbiz","openmeetings","openoffice","orc","ozone","sentry","shiro","singa","sling","solr","spamassassin","spark","struts","tomcat","trafficcontrol","trafficserver","trafodion","zeppelin","zookeeper"],
    // which PMC are allowed to live allocate a CNA name from CVE Project
    pmcstrustedascna: ["none"],
    
    // The Mongodb URL where CVE entries and users are stored.
    // WARNING! Configure MongoDB authentication and use a strong password
    // WARNING! Ensure MongoDB is not reachable from the network. 
    // database:'mongodb://vulnogram:StringLongPass@127.0.0.1:27017/vulnogram'
    database: secrets.database,

    // Name of the organization that should be used in page titles etc.,
    orgName: ' ',

    // Name of the group that should be used in page titles etc.,
    groupName: ' ',

    //CNA contact address
    contact: 'security@apache.org',

    classification: 'This tool is based on Vulnogram, contact security@apache.org with any queries or problems',
    copyright: ' ',
    //copyright: 'Made with ' + package.name + ' ' + package.version,

    // Uncomment this line and set a random string to allow unauthenticated access to draft CVE entries that are in review-ready or publish-ready state via /review/<token>/ or /review/<token>/CVE-ID
    // This may be useful to share a link to the draft for internal reviews and only those with the link have access to the drafts.    
   //reviewToken: 'randomtoken',

    // port where this tool is running
    serverHost: '0.0.0.0',
    serverPort: 3555,
    basedir: '/',

    //Uncomment this block to enable HTTPs. Configure paths for valid SSL certificates. 
    // Either get them from your favorite Certificate Authority or generate self signed:
    // Keep these safe and secured and readable only by account running vulnogram process!
    // $ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem

    httpsOptions: {
        key: privateKey,
        cert: certificate,
	    ca: ca
/*        minVersion: 'TLSv1.2'*/
    },
    
    mitreURL: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=',
    defectURL: '',
    publicDefectURL: '',

    // ACE editor
    ace: 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.3/ace.js',
    aceHash: "sha384-rP/6HzF4Ap08EuRS9yaQsEPDqb8xS5WVTAzL7/LKTnUmJawbKoeSNyqHnNaiXY5X",
    // if you want this served locally, download ace editor to /public/js/ directory and point to that:
    //ace: '/js/ace.js',

    // JSON Editor
    jsoneditor: 'https://cdn.jsdelivr.net/npm/@json-editor/json-editor@1.2.1/dist/jsoneditor.min.js',
    jsoneditorHash: 'sha384-iSUg2WRV2cauD+nwMuv7ITxwSe+2heHjWFIOjiWk5/Yve5ovwg/t7qp3ht6VlQBL',
    // if you want this served locally, download above jsoneditor editor to /public/js/ directory and point to that:
    //jsoneditor: '/js/jsoneditor.min.js',

    usernameRegex: '[a-zA-Z0-9]{3,}',
    sections: [
        'cve',
    ],
    homepage: '/cve',

    // Configure addional custom ExpressJS routes.
    /*
    customRoutes: [
        {
            path:"/info",
            route: "./customRoutes/info"
        }
    ]
    */
};
