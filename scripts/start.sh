#!/usr/bin/env sh

sed -i -e "s/copyright.*/copyright : '$(git describe --tags)',/" config/conf.js
node app.js
