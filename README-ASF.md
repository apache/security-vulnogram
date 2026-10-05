# Notes on the ASF fork of Vulnogram

This fork adds a number of ASF-specific features,
such as:

* authorization based on the ASF OAuth
* sending various notification emails
* selecting which fields to encourage
* some ASF-specific autocompletes and validations
* allocate CVEs server-side through the ASF CVE
* short-lived, scoped API tokens for tools (see below)

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

## Development and production mode

`NODE_ENV` selects the mode. Only `NODE_ENV=production` turns on the parts
that reach outside the instance; anything else, including leaving it unset,
runs in development mode:

| | `NODE_ENV=production` | Unset or anything else |
|---|---|---|
| CVE allocation | Real IDs from CVE Services (`CVE_API_URL`, `CVE_API_USER`, `CVE_API_KEY`) | Fake `CVE-2000-…` IDs; CVE Services is not contacted |
| Publishing to cve.org | Pushed | Skipped |
| Notification email | Sent | Logged, not sent |
| `Strict-Transport-Security` header | Sent | Not sent |

The startup log shows which mode is active with a **PRODUCTION MODE** or
**DEVELOPMENT MODE** banner.

The live instance must set `NODE_ENV=production`;
[`pipservice-vulnogram.service`](pipservice-vulnogram.service) does.
[`pipservice-vulnogram-test.service`](pipservice-vulnogram-test.service)
does not, so the test instance runs in development mode.

## API tokens for tools

Tools authenticate with an `Authorization: Bearer <token>` header.
Tokens are bound to the login session that issued them, so they expire when it does (hours) and logging out revokes them.
A Bearer token is accepted only on `/cve5/CVE-*`, `/cve5/json/CVE-*` and `/allocatecve`, and Bearer requests are exempt from the CSRF check.

`/users/token` lists an unrestricted token, plus a token per PMC for each of these scopes:

| Scope | Allowed |
|---|---|
| `read` | `GET` / `HEAD` on `/cve5/CVE-*` and `/cve5/json/CVE-*` |
| `write` | any method on `/cve5/CVE-*` and `/cve5/json/CVE-*` |
| `allocate` | `/allocatecve`, for that PMC only |

A PMC token acts as its owner limited to that PMC, so it only reaches that PMC's records, even for security-team members.

`POST /allocatecve` with a Bearer token and a form or JSON body (`pmc`, `cvetitle`, optionally `messageid` and `listid`) answers with JSON:

| Status | Body |
|---|---|
| 200 | `{"cve_ids": ["CVE-2026-12345"]}`: the ID is reserved and its record created |
| 202 | `{"cve_ids": [], "message": "..."}`: the PMC can not allocate directly, so the request was mailed to security@apache.org |
| 400 | `{"message": "..."}`: missing `cvetitle` |
| 500 | `{"cve_ids": [...], "message": "..."}`: the ID is reserved but saving its record failed |
| 502 | `{"message": "..."}`: CVE Services returned an error |

### Getting a token from a tool

Instead of having the user copy a token from `/users/token`, a tool can ask for one through the browser.
The flow is the OAuth 2.0 loopback flow for native apps ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)) with PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), so the token never appears in a URL or in the browser history.

1. The tool listens on `http://127.0.0.1:<port>/` (or `http://[::1]:<port>/`), creates a random `state` and a PKCE `code_verifier`, and opens this URL in the browser:

   ```text
   /users/token/authorize?pmc=<pmc>&scope=read|write|allocate
       &redirect_uri=http://127.0.0.1:<port>/<path>&state=<state>
       &code_challenge=<base64url(sha256(code_verifier))>&code_challenge_method=S256
   ```

2. The user logs in if needed (ASF OAuth, MFA included), sees which PMC and scope the tool asks for, and approves or denies.

3. The browser is redirected to the tool with `?code=<code>&state=<state>`, or `?error=access_denied&state=<state>`.
   The tool must check that `state` matches.

4. The tool exchanges the code, which is single-use and valid for 60 seconds:

   ```shell
   curl -X POST https://cveprocess.apache.org/users/token/exchange \
     -H 'Content-Type: application/json' \
     -d '{"code": "<code>", "code_verifier": "<code_verifier>"}'
   ```

   The response is `{"access_token": "...", "token_type": "Bearer", "pmc": "...", "scope": "..."}`, or HTTP 400 `{"error": "invalid_grant"}`.

The server accepts only loopback IP literals as `redirect_uri` (not `localhost`), only the PMCs the user belongs to (any PMC for the security team), and only the `read`, `write` and `allocate` scopes.

The design, its assumptions and the invariants the implementation must keep are in [docs/design/browser-token-authorize.md](docs/design/browser-token-authorize.md).
