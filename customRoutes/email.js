const nodemailer = require("nodemailer");

// set from: (default security@) to: subject: text 

module.exports = {

    // TODO: This should figure out if security@ exists etc
    getpmclist: function (pmc) {
        var pmcemail = "private@"+pmc+".apache.org";
        if (pmc == "security") {
            pmcemail = "security@apache.org";
        }
        return pmcemail;
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
	let info = await transporter.sendMail(mailinfo);
	return info.messageId;
    }
}
