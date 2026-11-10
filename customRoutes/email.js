const nodemailer = require("nodemailer");
const conf = require('../config/conf');

// set from: (default security@) to: subject: text 

module.exports = {
    parseBcc: function (value) {
        if (typeof value !== 'string') {
            return [];
        }
        var seen = new Set();
        var out = [];
        for (var address of value.split(',')) {
            address = address.trim();
            if (!/^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(address)) {
                continue;
            }
            var key = address.toLowerCase();
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            out.push(address);
        }
        return out;
    },
    sendemail: async function (mailinfo)  {
	let transporter = nodemailer.createTransport({
	    sendmail: true,
	    newline: 'unix',
	    path: '/usr/sbin/sendmail',
	});
	if (!mailinfo.from) {
	    mailinfo.from = "cveprocess site <security@apache.org>";
	}
	if (!mailinfo.to) {
	    mailinfo.to = "ASF Security <security@apache.org>";
	}	
	if (conf.cveapiliveservice) {
		let info = await transporter.sendMail(mailinfo);
		return info.messageId;
	} else {
		console.log(mailinfo.text)
		return "(not live, no message id)"
	}
    }
}
