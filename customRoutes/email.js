const nodemailer = require("nodemailer");

// set from: (default security@) to: subject: text 

module.exports = {
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
