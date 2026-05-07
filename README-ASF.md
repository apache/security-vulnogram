# Notes on the ASF fork of Vulnogram

This fork adds a number of ASF-specific features,
such as:

* authorization based on the ASF OAuth
* sending various notification emails
* selecting which fields to encourage
* some ASF-specific autocompletes and validations
* allocate CVEs server-side through the ASF CVE

## Development

Create a `config/customsecrets.js` with:

```js
module.exports = {
    database: `mongodb://admin:admin@127.0.0.1:27017`,
}
```

* start mongodb with `docker compose up -d vulnogram-mongo`
* start the app with `node app.js`
