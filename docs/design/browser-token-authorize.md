# Design: browser-approved API tokens for tools

Status: proposed, implemented in [#264](https://github.com/apache/security-vulnogram/pull/264).
Refs [#246](https://github.com/apache/security-vulnogram/issues/246).

## How to review this document

This document is meant to be reviewed in two ways.

1. **Review the design.**
   Read [Assumptions](#assumptions) and [Alternatives](#alternatives-considered) and challenge them.
   If an assumption is wrong, the design is wrong, however good the code is.
2. **Check the implementation against the design.**
   [Invariants](#invariants) lists numbered, testable claims, each with the code that enforces it and the test that covers it.
   You can check them yourself, or hand this document and the PR diff to a coding agent, ask it to verify each invariant against the code, and ask it to report any code path that the invariants do not cover.

The idea is that humans spend their time on the design (is this the right problem, the right trade-off, the right trust boundaries), and agents do the systematic work of checking that the code does what the design says.

## Problem

Tools that call the Vulnogram API (for example the `vulnogram-api-setup` helper in apache/magpie) need a Bearer token.
Today the user has to open `/users/token`, find the right PMC and scope, and paste the token into the tool.
That is error-prone, encourages copying the most powerful token on the page, and leaves tokens in shell history and clipboards.

## Goals

- A tool can get a token for **one PMC and one scope** after the user approves it in the browser, with the normal ASF login (MFA included).
- The token never appears in a URL, the browser history, or server logs of the redirect.
- A PMC-scoped token can reach **only** that PMC's records, even when its owner is on the security team.
- A read-only scope exists for tools that only need to read records.
- Token lifetime and revocation do not change: a token dies with the login session that issued it.

## Non-goals

- Long-lived or refreshable tokens. Tokens stay session-bound.
- Tokens for anything other than records and CVE allocation.
- Third-party (non-loopback) clients. Only tools on the user's own machine are supported.
- Allocating CVEs through this flow. `allocate` tokens stay on `/users/token` only.

## Design

The flow is the OAuth 2.0 authorization code flow for native apps ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)) with PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)).

```text
tool (127.0.0.1:<port>)           browser                      Vulnogram
  | 1. listen, make state +         |                              |
  |    code_verifier, open URL ---> | GET /users/token/authorize ->| ASF OAuth login if needed
  |                                 |<---- consent page (PMC, scope, port)
  |                                 | POST approve/deny (CSRF) --->| issue one-time code,
  |                                 |<---- 302 to loopback --------|   save session
  |<-- GET /callback?code&state ----|                              |
  | 2. check state                                                 |
  | 3. POST /users/token/exchange {code, code_verifier} ---------->| check PKCE, spend code
  |<------------------ {access_token, token_type, pmc, scope} -----|
  | 4. Authorization: Bearer <token> on /cve5/... ---------------->| ensureAuthenticated:
  |                                                                |   scope check, narrow user
```

Components:

- `custom/tokenauthorize.js`: request validation, one-time codes, scope checks, user narrowing, and the three route handlers.
- `views/tokenauthorize.pug`: the consent page.
- `custom/asf.js`: route registration, and `/users/token` now fills in missing tokens instead of resetting the map.
- `app.js` `ensureAuthenticated`: delegates scope checks to `checkScopedToken` and narrows `req.user` with `narrowUser`.

The issued token is an ordinary per-PMC token in `session.tokens[pmc][scope]`, the map `/users/token` already uses, so `ensureAuthenticated` finds it the same way.

## Assumptions

These are the claims the design rests on. Each is a good place to push back.

- **A1. The loopback redirect is enough to identify "a tool on this machine".**
  The server does not register clients or ports.
  Any local process can start a request, but the user must approve it on a page that names the PMC, scope and port.
  The page tells the user to approve only a request they just started.
- **A2. PKCE makes a stolen code useless.**
  Another local process that grabs the redirect (for example by binding the same port first) gets the code but not the verifier, so it cannot redeem it.
- **A3. Codes can live in process memory.**
  Vulnogram runs as a single process with an in-memory session store, so a restart already logs everyone out.
  Losing one-minute codes on restart is acceptable.
  **This breaks if Vulnogram ever runs as several instances**; codes (and sessions) would need a shared store.
- **A4. Record access control is driven by `req.user.pmcs`.**
  Narrowing `req.user.pmcs` to the token's PMC is what confines a token to that PMC.
  This relies on record routes deriving access from `req.user.pmcs`.
- **A5. Session-bound lifetime is the right lifetime.**
  Tools that run for longer than a login session have to repeat the flow. This is a deliberate trade-off against refresh tokens.
- **A6. Bearer requests are safe to exempt from CSRF.**
  Browsers do not attach an `Authorization` header on their own and CORS is locked down, so a third-party site cannot forge a Bearer request.
- **A7. `localhost` is not trustworthy as a redirect host.**
  It can resolve somewhere other than loopback (RFC 8252 §8.3), so only `127.0.0.1` and `[::1]` are accepted.

## Invariants

Each invariant is a claim about the code on this branch.
"Test" refers to `unittest/tokenauthorize.js` unless stated otherwise.

| # | Invariant | Enforced in | Test |
|---|---|---|---|
| I1 | `redirect_uri` is accepted only if it is `http:`, host `127.0.0.1` or `[::1]`, has an explicit port, and has no userinfo and no fragment. | `validateRedirectUri` | redirect URI block |
| I2 | The authorize request is refused unless the user is a member of `pmc` or of the security team (`conf.admingroupname`). | `validateAuthorizeRequest` | "not a member" cases |
| I3 | Only `read` and `write` can be requested through the browser flow; `allocate` cannot. | `SCOPES`, `validateAuthorizeRequest` | scope cases |
| I4 | `code_challenge_method` must be `S256`; `plain` is refused. | `validateAuthorizeRequest` | S256 case |
| I5 | The approve/deny decision is a POST with a CSRF token, and is re-validated on the server (the form's hidden fields are not trusted). | `authorizeDecision`, `tokenauthorize.pug` | not covered |
| I6 | A token is issued only on `decision=approve`; any other value redirects with `error=access_denied`. | `authorizeDecision` | not covered |
| I7 | The token never appears in a URL: the redirect carries only `code` and `state`, and the token is returned only in the `exchange` response body, sent with `Cache-Control: no-store`. | `authorizeDecision`, `exchange` | not covered |
| I8 | A code is 256 bits of randomness, is valid for 60 seconds, and is spent on the first redemption attempt, whether it succeeds or not. | `issueCode`, `redeemCode` | redeem/expiry cases |
| I9 | A code is redeemed only with a verifier whose `base64url(sha256(verifier))` equals the stored challenge, compared in constant time. | `redeemCode` | wrong-verifier case |
| I10 | The session is saved before the redirect, so the token is usable as soon as the tool gets the code. | `authorizeDecision` | not covered |
| I11 | Issuing a code does not remove or replace other tokens in the session; re-approving the same PMC and scope reuses the existing token. | `issueCode` | "left alone" / reuse cases |
| I12 | Visiting `/users/token` does not remove tokens issued through the browser flow. | `asf.js` `token` | not covered |
| I13 | `read` tokens are allowed only for `GET`/`HEAD` on `/cve5/CVE-*` and `/cve5/json/CVE-*`; `write` tokens only on those paths; `allocate` tokens only on `/allocatecve`. | `checkScopedToken` | scope-check cases |
| I14 | A PMC-scoped token acts as its owner with `pmcs` set to exactly `[pmc]`, for every scope including the existing `write` and `allocate`, and the session's own user object is not modified. | `narrowUser`, `ensureAuthenticated` | `narrowUser` case |
| I15 | A Bearer token cannot reach `/users/token/authorize` or `/users/token`, so a token cannot be used to mint another token. | `ensureAuthenticated` path allow-list | not covered |
| I16 | `/users/token/exchange` needs no session or CSRF token; it is authenticated only by code plus verifier. | route registration in `asf.js` | not covered |
| I17 | User-supplied values on the consent page (`pmc`, `scope`, `state`, port) are HTML-escaped. | `tokenauthorize.pug` (Pug `=` / `#{}`) | manual check |

Invariants marked "not covered" are enforced in route handlers or templates that the unit tests do not load.
They are good candidates for an agent (or a human) to check by reading the code, and for an end-to-end test.

## Behaviour changes for existing tokens

- Existing `write` and `allocate` PMC tokens now act as their owner limited to their PMC (I14).
  Before, they authenticated as the full user.
- `/users/token` lists a `read` token per PMC next to `allocate` and `write`.

## Alternatives considered

- **Keep copy-paste from `/users/token`.**
  No new code, but it keeps the problems described above.
- **Device authorization grant (RFC 8628).**
  Works without a local listener, but needs polling, a user code to type, and more server state.
  Every supported tool runs on the user's machine, so the loopback flow is simpler.
- **Return the token directly in the redirect (implicit-style).**
  Simpler, but it puts the token in the browser history and in any local process that catches the redirect.
  PKCE plus a code avoids both.
- **Separate long-lived API keys with their own store and revocation UI.**
  More useful for automation, but a much larger change to how Vulnogram handles credentials. Out of scope.

## Open questions

- Should the consent page show the tool's name? It is self-declared by the tool, so it could mislead, which is why the page shows only the port.
- Is there appetite for a shared code/session store, which A3 would need if Vulnogram is ever scaled out?
- End-to-end verification against a dev instance (Mongo + oauth.apache.org) with the magpie reference client is still pending.
