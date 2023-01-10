const express = require('express');
const protected = express.Router();

const { exec } = require('child_process');

module.exports = function(req, res) {
  exec('git describe --tags', (error, stdout, stderr) => {
    if (error) {
        req.flash('error', 'unable to determine version')
        req.flash('error', stderr)
        res.render('blank')
    } else {
        req.flash('info', stdout)
        res.render('blank');
    }
    res.end();
  });
};
