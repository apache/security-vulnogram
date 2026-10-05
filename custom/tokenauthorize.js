// ASF: browser-approved, scoped API tokens for command-line tools.
//
// A tool on the user's machine opens
//
//   /users/token/authorize?pmc=<pmc>&scope=read|write|allocate
//       &redirect_uri=http://127.0.0.1:<port>/<path>&state=<opaque>
//       &code_challenge=<challenge>&code_challenge_method=S256
//
// in the browser. After the usual ASF OAuth login (MFA included) the user
// sees what is being asked for and approves or denies it. On approval the
// browser is sent to the tool's loopback listener with a one-time code, which
// the tool exchanges, together with its PKCE code verifier, for the token at
// POST /users/token/exchange.
//
// This is the OAuth 2.0 flow for native apps (RFC 8252, with PKCE per
// RFC 7636): the token never appears in a URL or in the browser history, and
// a local process that intercepts the redirect cannot redeem the code without
// the verifier. The token itself is an ordinary /users/token token, bound to
// the user's session and limited to one PMC and one scope.

const crypto = require('crypto');
const conf = require('../config/conf');

const SCOPES = ['read', 'write', 'allocate'];
const CODE_TTL_MS = 60 * 1000;
const PMC_RE = /^[a-z0-9-]{1,64}$/;
const STATE_RE = /^[\x21-\x7e]{1,512}$/;
// RFC 7636: the challenge is base64url(sha256(verifier)) without padding, and
// the verifier is 43-128 characters from the unreserved set.
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43,128}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;

// One-time codes, keyed by code. In memory, like the session store: a restart
// drops both, which is fine for codes that live a minute.
const codes = new Map();

// Only loopback IP literals, as RFC 8252 section 7.3 recommends: "localhost"
// can be resolved elsewhere, and any other host would send the code off the
// user's machine.
function validateRedirectUri(value) {
    if (typeof value !== 'string') return null;
    let u;
    try {
        u = new URL(value);
    } catch (e) {
        return null;
    }
    if (u.protocol !== 'http:') return null;
    if (u.hostname !== '127.0.0.1' && u.hostname !== '[::1]') return null;
    if (!u.port) return null;
    if (u.username || u.password || u.hash) return null;
    return u.href;
}

// Validate the parameters of an authorize request, from the query string (the
// consent page) or the form body (the decision). Returns {error} or {request}.
function validateAuthorizeRequest(params, user) {
    params = params || {};
    const pmcs = (user && user.pmcs) || [];
    const pmc = params.pmc;
    if (typeof pmc !== 'string' || !PMC_RE.test(pmc)) {
        return { error: 'Missing or malformed pmc.' };
    }
    if (!pmcs.includes(pmc) && !pmcs.includes(conf.admingroupname)) {
        return { error: 'You are not a member of the ' + pmc + ' PMC.' };
    }
    if (!SCOPES.includes(params.scope)) {
        return { error: 'scope must be one of: ' + SCOPES.join(', ') + '.' };
    }
    const redirectUri = validateRedirectUri(params.redirect_uri);
    if (!redirectUri) {
        return { error: 'redirect_uri must be http://127.0.0.1:<port>/... or http://[::1]:<port>/...' };
    }
    if (typeof params.state !== 'string' || !STATE_RE.test(params.state)) {
        return { error: 'Missing or malformed state.' };
    }
    if (params.code_challenge_method !== 'S256') {
        return { error: 'code_challenge_method must be S256.' };
    }
    if (typeof params.code_challenge !== 'string' || !CHALLENGE_RE.test(params.code_challenge)) {
        return { error: 'Missing or malformed code_challenge.' };
    }
    return {
        request: {
            pmc: pmc,
            scope: params.scope,
            redirectUri: redirectUri,
            state: params.state,
            codeChallenge: params.code_challenge
        }
    };
}

function sweepCodes(now) {
    for (const [code, entry] of codes) {
        if (entry.expires < now) codes.delete(code);
    }
}

// Register the PMC/scope token in the session, the same map /users/token and
// ensureAuthenticated use, and return a one-time code that redeems it.
function issueCode(session, request, now = Date.now()) {
    session.tokens = session.tokens || {};
    session.tokens[request.pmc] = session.tokens[request.pmc] || {};
    const token = session.tokens[request.pmc][request.scope] || crypto.randomUUID();
    session.tokens[request.pmc][request.scope] = token;

    sweepCodes(now);
    const code = crypto.randomBytes(32).toString('base64url');
    codes.set(code, {
        token: token,
        pmc: request.pmc,
        scope: request.scope,
        challenge: request.codeChallenge,
        expires: now + CODE_TTL_MS
    });
    return code;
}

// Return {token, pmc, scope} for a valid code and verifier, else null. A code
// is spent on the first attempt, right or wrong.
function redeemCode(code, verifier, now = Date.now()) {
    if (typeof code !== 'string' || typeof verifier !== 'string') return null;
    const entry = codes.get(code);
    if (!entry) return null;
    codes.delete(code);
    if (entry.expires < now) return null;
    if (!VERIFIER_RE.test(verifier)) return null;
    const expected = Buffer.from(entry.challenge);
    const actual = Buffer.from(crypto.createHash('sha256').update(verifier).digest('base64url'));
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
        return null;
    }
    return { token: entry.token, pmc: entry.pmc, scope: entry.scope };
}

// Decide whether a PMC-scoped token of kind `op` may be used for this request.
// Returns null when it may, else the message to reject it with.
function checkScopedToken(op, method, url) {
    const isRecord = url.startsWith('/cve5/CVE-') || url.startsWith('/cve5/json/CVE-');
    if (op == 'allocate' && url != '/allocatecve') {
        return 'allocate token not valid for this endpoint';
    }
    if (op == 'write' && !isRecord) {
        return 'write token not valid for this endpoint';
    }
    if (op == 'read' && !(isRecord && (method == 'GET' || method == 'HEAD'))) {
        return 'read token not valid for this request';
    }
    return null;
}

// The user a PMC-scoped token acts as: the token owner, limited to that PMC.
// Every record ACL checks req.user.pmcs, so this is what keeps a token for one
// PMC away from the records of the owner's other PMCs (and drops the security
// team's access to everything).
function narrowUser(user, pmc) {
    return Object.assign({}, user, { pmcs: [pmc] });
}

function authorizeForm(req, res) {
    const v = validateAuthorizeRequest(req.query, req.user);
    if (v.error) {
        res.status(400);
        return res.render('tokenauthorize', { error: v.error });
    }
    res.render('tokenauthorize', {
        request: v.request,
        redirectHost: new URL(v.request.redirectUri).host,
        username: req.user.username,
        csrfToken: req.csrfToken()
    });
}

function authorizeDecision(req, res, next) {
    const v = validateAuthorizeRequest(req.body, req.user);
    if (v.error) {
        res.status(400);
        return res.render('tokenauthorize', { error: v.error });
    }
    const target = new URL(v.request.redirectUri);
    if (req.body.decision !== 'approve') {
        target.searchParams.set('error', 'access_denied');
        target.searchParams.set('state', v.request.state);
        return res.redirect(target.href);
    }
    const code = issueCode(req.session, v.request);
    target.searchParams.set('code', code);
    target.searchParams.set('state', v.request.state);
    // The tool uses the token straight after the redirect, and ensureAuthenticated
    // finds it by scanning the session store, so store the session first.
    req.session.save(function (err) {
        if (err) return next(err);
        res.redirect(target.href);
    });
}

function exchange(req, res) {
    res.set('Cache-Control', 'no-store');
    const body = req.body || {};
    const grant = redeemCode(body.code, body.code_verifier);
    if (!grant) {
        res.status(400);
        return res.json({ error: 'invalid_grant' });
    }
    res.json({
        access_token: grant.token,
        token_type: 'Bearer',
        pmc: grant.pmc,
        scope: grant.scope
    });
}

module.exports = {
    SCOPES,
    validateRedirectUri,
    validateAuthorizeRequest,
    issueCode,
    redeemCode,
    checkScopedToken,
    narrowUser,
    authorizeForm,
    authorizeDecision,
    exchange
};
