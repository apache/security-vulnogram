# Notes on the ASF fork of Vulnogram

This fork adds a number of ASF-specific features,
such as:

* authorization based on the ASF OAuth
* sending various notification emails
* selecting which fields to encourage
* some ASF-specific autocompletes and validations
* allocate CVEs server-side through the ASF CVE

## Setting up a development environment

The recommended dev setup runs MongoDB in a container and the
Vulnogram app on the host.

### One-time setup

1. Install Node dependencies:

   ```shell
   npm install
   ```

2. Copy `example-asf.env` to `.env`, then open `.env` and uncomment the
   development overrides at the top of the file:

   ```shell
   cp example-asf.env .env
   ```

3. Generate a self-signed TLS certificate (required because the
   `oauth.apache.org` callback URL must use HTTPS):

   ```shell
   openssl req -x509 -newkey rsa:2048 -nodes \
     -keyout key.pem -out cert.pem -days 365 \
     -subj "/CN=localhost" \
     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
   ```

   The browser will warn about the untrusted certificate on first visit; click through to accept it.

### Every run

1. Start MongoDB in a container:

   ```shell
   docker compose up -d vulnogram-mongo
   ```

2. Start the app on the host:

   ```shell
   node app.js
   ```

The app listens on `http://0.0.0.0:3555` by default and uses `oauth.apache.org` for authentication.