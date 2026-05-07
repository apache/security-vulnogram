const fs = require("fs");
const process = require("process");
var package = require("../package.json");

// Production mode talks to the real CVE Services API and sends notification
// emails, opt in explicitly with `NODE_ENV=production`.
// Anything else (including unset) is treated as non-production.
const prod = process.env.NODE_ENV === "production";
if (prod) {
    console.log("");
    console.log("PRODUCTION MODE");
    console.log("");
    console.log("Running in 'production' mode, this will send email");
    console.log("and allocate real CVEs. For testing, use NODE_ENV=development");
    console.log("");
}

const cveapiurl = prod
    ? process.env.CVE_API_URL || "https://cveawg.mitre.org/api"
    : "http://localhost:3555";

// Built from env so secrets stay out of the repo. See example.env.
const cveapiheaders = {
    "CVE-API-ORG": process.env.CVE_API_ORG || "apache",
    "CVE-API-USER": process.env.CVE_API_USER || "",
    "CVE-API-KEY": process.env.CVE_API_KEY || "",
};

// HTTPS is required (the OAuth callback URL must use it).
// Override the paths with VULNOGRAM_TLS_KEY / VULNOGRAM_TLS_CERT / VULNOGRAM_TLS_CA;
// the defaults assume the production Let's Encrypt layout on security-vm-he-fi.apache.org.
const tlsKeyPath = process.env.VULNOGRAM_TLS_KEY
    || "/etc/letsencrypt/live/security-vm-he-fi.apache.org/privkey.pem";
const tlsCertPath = process.env.VULNOGRAM_TLS_CERT
    || "/etc/letsencrypt/live/security-vm-he-fi.apache.org/cert.pem";
const tlsCaPath = process.env.VULNOGRAM_TLS_CA
    || "/etc/letsencrypt/live/security-vm-he-fi.apache.org/chain.pem";

const httpsOptions = {
    key: fs.readFileSync(tlsKeyPath, "utf8"),
    cert: fs.readFileSync(tlsCertPath, "utf8"),
    minVersion: "TLSv1.2",
};
// Self-signed dev certs have no CA chain; only attach one if present.
if (fs.existsSync(tlsCaPath)) {
    httpsOptions.ca = fs.readFileSync(tlsCaPath, "utf8");
}

const database =
    process.env.VULNOGRAM_DB_URL ||
    `mongodb://${process.env.MONGO_INITDB_ROOT_USERNAME || "admin"}:${process.env.MONGO_INITDB_ROOT_PASSWORD || "admin"}@${process.env.MONGO_HOST || "127.0.0.1"}:${process.env.MONGO_PORT || "27017"}`;

module.exports = {
    // CVE automation configuration and CNA name
    cveorgid: "'f0158376-9dc2-43b6-827c-5f631a4d8d09'",
    cveapiheaders: cveapiheaders,
    cveapiurl: cveapiurl,
    cveapishortname: "apache",
    cveapiliveservice: prod,
    // which PMC is admin group?
    admingroupname: "security",
    // which PMC have a security@ address?
    pmcswithsecurityemails: ["airflow","ambari","commons","couchdb","dolphinscheduler","dubbo","fineract","geronimo","guacamole","hadoop","hive","httpd","ignite","jackrabbit","kafka","libcloud","logging","lucene","metron","milagro","nifi","ofbiz","openmeetings","openoffice","orc","ozone","sentry","shiro","singa","sling","solr","spamassassin","spark","struts","tomcat","trafficcontrol","trafficserver","trafodion","zeppelin","zookeeper"],
    // which PMC are allowed to live allocate a CNA name from CVE Project
    pmcstrustedascna: ["*","-zeppelin"],

    // The Mongodb URL where CVE entries and users are stored.
    // WARNING! Configure MongoDB authentication and use a strong password
    // WARNING! Ensure MongoDB is not reachable from the network.
    database: database,
    //database: `mongodb://vulnogram:StrongLongPass@127.0.0.1:27017/vulnogram`,
    // Name of the organization that should be used in page titles etc.,
    orgName: ' ',

    // Name of the group that should be used in page titles etc.,
    groupName: ' ',

    //CNA contact address
    contact: 'security@apache.org',

    classification: 'This tool is based on Vulnogram, contact security@apache.org with any queries or problems',
    copyright: ' ',

    // Uncomment this line and set a random string to allow unauthenticated access to draft CVE entries that are in review-ready or publish-ready state via /review/<token>/ or /review/<token>/CVE-ID
    // This may be useful to share a link to the draft for internal reviews and only those with the link have access to the drafts.
   //reviewToken: 'randomtoken',

    // port where this tool is running
    serverHost: process.env.VULNOGRAM_HOST || '0.0.0.0',
    serverPort: process.env.VULNOGRAM_PORT || 3555,
    basedir: '/',

    httpsOptions: httpsOptions,

    mitreURL: 'https://www.cve.org/CVERecord?id=',
    defectURL: '',
    publicDefectURL: '',

    // ACE editor
    ace: 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.13/ace.js',
    aceHash: "sha512-OMjy8oWtPbx9rJmoprdaQdS2rRovgTetHjiBf7RL7LvRSouoMLks5aIcgqHb6vGEAduuPdBTDCoztxLR+nv45g==",
    // if you want this served locally, download ace editor to /public/js/ directory and point to that:
    //ace: '/js/ace.js',
    //aceHash: "sha512-GoORoNnxst42zE3rYPj4bNBm0Q6ZRXKNH2D9nEmNvVF/z24ywVnijAWVi/09iBiVDQVf3UlZHpzhAJIdd9BXqw==",


    // JSON Editor
    jsoneditor: 'https://cdnjs.cloudflare.com/ajax/libs/json-editor/2.8.0/jsoneditor.min.js',
    jsoneditorHash: 'sha512-8y8kuGFzNGSgACEMNnXJGhOQaLAd4P9MdCXnJ37QjGTBPRrD5FCEVEKj/93xNihQehkO3yVKnOECFWGxxBsveQ==',
    // if you want this served locally, download above jsoneditor editor to /public/js/ directory and point to that:
    //jsoneditor: '/js/jsoneditor.min.js',

    // ajv - JSON schema draft-07 validation
    // NOTE -- including ajv is experimental and can be excluded if desired by commenting out the next two lines
    ajv: 'https://cdnjs.cloudflare.com/ajax/libs/ajv/8.12.0/ajv7.min.js',
    ajvHash: 'sha512-U2SW9Ihh3GF6F8gP8QgLS+I244xnM5pFCh3cigpw7bAzUDnKDlxdlFL4kjyXTle8SJl/tJ0gdnwd44Eb3hLG/Q==',
    // if you want this served locally, download above ajv to /public/js/ directory and point to that:
    //ajv: '/js/ajv7.min.js',
    //ajvHash: 'sha512-U2SW9Ihh3GF6F8gP8QgLS+I244xnM5pFCh3cigpw7bAzUDnKDlxdlFL4kjyXTle8SJl/tJ0gdnwd44Eb3hLG/Q==',

    usernameRegex: '[a-zA-Z0-9]{3,}',
    sections: [
        'cve5',
        'cve',
    ],
    homepage: '/cve5',

    // Configure addional custom ExpressJS routes.
/*
    customRoutes: [
        {
            path:"/info",
            route: "./customRoutes/info"
        }
    ]*/
};
