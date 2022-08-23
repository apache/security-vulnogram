const { v4: uuidv4 } = require('uuid');
const request = require('request');
const express = require('express');
const conf = require('../config/conf');

var self = module.exports = {
    asfinit: function (app) {
    },
    asfroutes: function (ensureAuthenticated, app) {
    },
}
