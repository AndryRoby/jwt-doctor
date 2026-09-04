// doctor-jwt.js: JWT Doctor core logic.
//
// Pure, deterministic, 100% client-side: given a pasted JWT (Access token,
// ID token, or a hand-built string), the values you expect it to carry
// (issuer, audience, algorithm, clock-skew tolerance), and optionally a
// verification key (an HMAC secret, or an RSA/EC public key as PEM or JWK),
// decodes the header and payload, checks every structural and claim rule the
// JOSE/JWT specs define, verifies the signature with the Web Crypto API when
// a key is supplied, and reports the precise problem plus a copy-paste fix.
//
// Nothing in this file makes a network request, and the token you paste is
// never sent anywhere: signature verification runs entirely through
// window.crypto.subtle in your own browser.
//
// This is a sibling in the "Doctor" family (after the Google OAuth redirect,
// Supabase redirect, and Flutter/Expo Supabase Doctors): same diagnose()
// shape, same zero-dependency single-file design, different domain: RFC 7519
// (JWT) / RFC 7515 (JWS) compliance instead of a redirect_uri allow-list.
//
// Rules implemented here are sourced from:
//  - https://datatracker.ietf.org/doc/html/rfc7519
//      ("A JWT is represented as a sequence of URL-safe parts separated by
//      period ('.') characters. Each part contains a base64url-encoded
//      value."; "exp" claim: "the current date/time MUST be before the
//      expiration date/time listed in the 'exp' claim... Implementers MAY
//      provide for some small leeway, usually no more than a few minutes, to
//      account for clock skew."; "nbf": "the current date/time MUST be after
//      or equal to the not-before date/time"; "iat": "identifies the time at
//      which the JWT was issued"; "iss": "a case-sensitive string containing
//      a StringOrURI value"; "aud": "the 'aud' value is an array of
//      case-sensitive strings... In the special case when the JWT has one
//      audience, the 'aud' value MAY be a single case-sensitive string";
//      "An Unsecured JWT is a JWS using the 'alg' Header Parameter value
//      'none' and with the empty string for its JWS Signature value")
//  - https://datatracker.ietf.org/doc/html/rfc7515
//      (JWS Compact Serialization: "BASE64URL(UTF8(JWS Protected Header)) ||
//      '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)",
//      "resulting in exactly two delimiting period characters"; "alg" header:
//      "MUST be present and MUST be understood and processed by
//      implementations"; unsecured JWS: "Unsecured JWSs use the 'alg' value
//      'none'"; base64url: "the URL- and filename-safe character set defined
//      in Section 5 of RFC 4648, with all trailing '=' characters omitted")
//  - https://github.com/auth0/node-jsonwebtoken#errors--codes
//      (jwt.verify() error messages this tool's wording is deliberately
//      close to, so the two never contradict each other: TokenExpiredError
//      "jwt expired" + expiredAt; JsonWebTokenError "jwt malformed" (not
//      three dot-separated parts), "invalid signature", "jwt audience
//      invalid. expected: [OPTIONS AUDIENCE]", "jwt issuer invalid.
//      expected: [OPTIONS ISSUER]"; NotBeforeError "jwt not active" + date)
//  - https://github.com/panva/jose (error classes; also
//      https://github.com/panva/jose/blob/main/docs/jwt/verify/functions/jwtVerify.md)
//      (JWTExpired / ERR_JWT_EXPIRED "a JWT is expired";
//      JWTClaimValidationFailed / ERR_JWT_CLAIM_VALIDATION_FAILED "JWT
//      Claims Set validation fails" (iss/aud/sub mismatches);
//      JWSSignatureVerificationFailed / ERR_JWS_SIGNATURE_VERIFICATION_FAILED
//      "JWS signature verification fails"; JWSInvalid / ERR_JWS_INVALID "a
//      JWS is invalid"; jwtVerify's clockTolerance option for clock skew)
//
// Works as an ES module (import { diagnose, expectedValues } from
// './doctor-jwt.js') and, when loaded with <script type="module">, also
// publishes window.JwtDoctor = { diagnose, expectedValues } for console/debug
// use. Signature verification uses window.crypto.subtle when available (any
// modern browser, and Node 19+ via globalThis.crypto); in an environment
// without Web Crypto, diagnose() still runs every other check and reports
// signature status as "not checked" instead of throwing.

// ───────────────────────── small helpers ─────────────────────────

function safeStr(v) {
  return typeof v === 'string' ? v : '';
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

function base64UrlToBytes(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  // Node.js fallback (used by tests.mjs, never by the browser bundle).
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function bytesToUtf8(bytes) {
  if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  return Buffer.from(bytes).toString('utf8'); // Node fallback
}

function decodeBase64UrlJson(part, label) {
  if (!part) return { ok: false, error: `${label} is empty` };
  if (!B64URL_RE.test(part)) return { ok: false, error: `${label} contains characters outside the base64url alphabet (A-Z a-z 0-9 - _)` };
  let bytes;
  try {
    bytes = base64UrlToBytes(part);
  } catch (e) {
    return { ok: false, error: `${label} is not valid base64url: ${e.message}` };
  }
  let text;
  try {
    text = bytesToUtf8(bytes);
  } catch (e) {
    return { ok: false, error: `${label} did not decode to valid UTF-8` };
  }
  try {
    return { ok: true, value: JSON.parse(text), raw: text };
  } catch (e) {
    return { ok: false, error: `${label} decoded but is not valid JSON: ${e.message}` };
  }
}

function base64UrlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function utf8ToBytes(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  return new Uint8Array(Buffer.from(str, 'utf8')); // Node fallback
}

// Cleans up a pasted token: strips a leading "Bearer " prefix, wrapping
// quotes, and outer whitespace/newlines: all common paste artifacts that
// otherwise masquerade as "jwt malformed".
function cleanPastedToken(raw) {
  let s = safeStr(raw);
  const original = s;
  let trimmed = s.trim();
  let hadBearer = false;
  let hadQuotes = false;
  let hadWhitespace = trimmed !== original;
  if (/^bearer\s+/i.test(trimmed)) {
    trimmed = trimmed.replace(/^bearer\s+/i, '');
    hadBearer = true;
  }
  if ((trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length > 1) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length > 1)) {
    trimmed = trimmed.slice(1, -1);
    hadQuotes = true;
  }
  trimmed = trimmed.trim();
  // Internal whitespace (e.g. the token got line-wrapped) also counts.
  if (/\s/.test(trimmed)) hadWhitespace = true;
  const stripped = trimmed.replace(/\s+/g, '');
  return { cleaned: stripped, hadBearer, hadQuotes, hadWhitespace: hadWhitespace && stripped !== trimmed.replace(/\s/g, '') ? true : hadWhitespace };
}

// ───────────────────────── time helpers ─────────────────────────

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function isNumericDate(v) {
  return typeof v === 'number' && isFinite(v);
}

function fmtTime(numericDate) {
  if (!isNumericDate(numericDate)) return null;
  const d = new Date(numericDate * 1000);
  if (isNaN(d.getTime())) return null;
  return { iso: d.toISOString(), unix: numericDate };
}

function relTime(numericDate, refSeconds) {
  if (!isNumericDate(numericDate)) return null;
  const diff = numericDate - refSeconds;
  const abs = Math.abs(diff);
  const past = diff < 0;
  let mag, unit;
  if (abs < 60) { mag = abs; unit = 'second'; }
  else if (abs < 3600) { mag = Math.round(abs / 60); unit = 'minute'; }
  else if (abs < 86400) { mag = Math.round(abs / 3600); unit = 'hour'; }
  else if (abs < 86400 * 365) { mag = Math.round(abs / 86400); unit = 'day'; }
  else { mag = Math.round(abs / (86400 * 365)); unit = 'year'; }
  const plural = mag === 1 ? '' : 's';
  return past ? `${mag} ${unit}${plural} ago` : `in ${mag} ${unit}${plural}`;
}

// ───────────────────────── algorithm helpers ─────────────────────────

const HMAC_ALGS = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
const RSA_ALGS = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' };
const RSA_PSS_ALGS = { PS256: 'SHA-256', PS384: 'SHA-384', PS512: 'SHA-512' };
const EC_ALGS = { ES256: { hash: 'SHA-256', curve: 'P-256' }, ES384: { hash: 'SHA-384', curve: 'P-384' }, ES512: { hash: 'SHA-512', curve: 'P-521' } };

function algFamily(alg) {
  if (HMAC_ALGS[alg]) return 'hmac';
  if (RSA_ALGS[alg]) return 'rsa';
  if (RSA_PSS_ALGS[alg]) return 'rsa-pss';
  if (EC_ALGS[alg]) return 'ec';
  if (alg === 'none') return 'none';
  return 'unknown';
}

function keyKindMatchesAlg(keyType, alg) {
  const fam = algFamily(alg);
  if (keyType === 'hmac-secret') return fam === 'hmac';
  if (keyType === 'rsa-public-pem' || keyType === 'jwk') return fam === 'rsa' || fam === 'rsa-pss' || fam === 'ec';
  return true;
}

function pemToArrayBuffer(pem) {
  const b64 = safeStr(pem)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!b64) throw new Error('empty PEM body');
  const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

const cryptoObj = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) ? globalThis.crypto : null;

async function importVerifyKey(alg, key) {
  if (!cryptoObj) throw new Error('Web Crypto (crypto.subtle) is not available in this environment');
  const fam = algFamily(alg);
  if (key.type === 'hmac-secret') {
    if (fam !== 'hmac') throw new Error(`"${alg}" is not an HMAC algorithm; a pasted secret only verifies HS256/HS384/HS512`);
    const hash = HMAC_ALGS[alg];
    return cryptoObj.subtle.importKey('raw', utf8ToBytes(key.value), { name: 'HMAC', hash }, false, ['verify']);
  }
  if (key.type === 'rsa-public-pem') {
    const spki = pemToArrayBuffer(key.value);
    if (fam === 'rsa') {
      return cryptoObj.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: RSA_ALGS[alg] }, false, ['verify']);
    }
    if (fam === 'rsa-pss') {
      return cryptoObj.subtle.importKey('spki', spki, { name: 'RSA-PSS', hash: RSA_PSS_ALGS[alg] }, false, ['verify']);
    }
    if (fam === 'ec') {
      return cryptoObj.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: EC_ALGS[alg].curve }, false, ['verify']);
    }
    throw new Error(`"${alg}" cannot be verified with a public-key PEM`);
  }
  if (key.type === 'jwk') {
    let jwk;
    try { jwk = typeof key.value === 'string' ? JSON.parse(key.value) : key.value; } catch (e) { throw new Error('JWK is not valid JSON'); }
    if (fam === 'rsa') return cryptoObj.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: RSA_ALGS[alg] }, false, ['verify']);
    if (fam === 'rsa-pss') return cryptoObj.subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: RSA_PSS_ALGS[alg] }, false, ['verify']);
    if (fam === 'ec') return cryptoObj.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: EC_ALGS[alg].curve }, false, ['verify']);
    throw new Error(`"${alg}" cannot be verified with a JWK`);
  }
  throw new Error('unknown key type');
}

function verifyAlgorithmParams(alg) {
  const fam = algFamily(alg);
  if (fam === 'hmac') return { name: 'HMAC' };
  if (fam === 'rsa') return { name: 'RSASSA-PKCS1-v1_5' };
  if (fam === 'rsa-pss') return { name: 'RSA-PSS', saltLength: RSA_PSS_ALGS[alg] === 'SHA-256' ? 32 : RSA_PSS_ALGS[alg] === 'SHA-384' ? 48 : 64 };
  if (fam === 'ec') return { name: 'ECDSA', hash: EC_ALGS[alg].hash };
  return null;
}

// DER (ASN.1) ECDSA signatures are not what Web Crypto's ECDSA verify
// expects for JWS: JWS ES256/384/512 signatures are raw fixed-length r||s
// concatenations (RFC 7515 doesn't restate this: it's inherited from the
// underlying ECDSA JOSE encoding every JWT library follows), so no
// conversion is needed here; this comment exists so a future edit doesn't
// "fix" a working raw-format verify into a broken DER one.
async function verifySignature(alg, key, signingInput, signatureBytes) {
  const cryptoKey = await importVerifyKey(alg, key);
  const params = verifyAlgorithmParams(alg);
  return cryptoObj.subtle.verify(params, cryptoKey, signatureBytes, utf8ToBytes(signingInput));
}

// ───────────────────────── provider heuristics ─────────────────────────

function detectProviderHints(header, payload, problems, pushProblem) {
  const iss = safeStr(payload && payload.iss);
  // Supabase: anon/service_role keys are themselves JWTs signed with the
  // project's JWT secret, and are easy to confuse with a user's access
  // token; the payload shape (role: "anon" | "service_role", no "sub")
  // is the tell.
  if (payload && (payload.role === 'anon' || payload.role === 'service_role') && !payload.sub) {
    pushProblem(problems, {
      severity: 'low',
      code: 'supabase_project_key_not_user_token',
      message: `payload.role is "${payload.role}" with no "sub" claim: this looks like a Supabase project API key (anon or service_role), not a user's access token. Project keys are signed with the project's JWT secret from Project Settings → API and never expire the same way user sessions do; verifying one here confirms the JWT secret, not a user's login.`,
      path: 'payload.role',
    });
  }
  // Firebase: a custom token (minted by the Admin SDK, signed with a
  // service-account RSA key, alg RS256) is easy to confuse with the ID
  // token a client gets back after signInWithCustomToken() exchanges it
  // (a Google-signed RS256 JWT with iss/aud of
  // https://securetoken.google.com/<project-id>). The custom token has a
  // "uid" claim and its aud is the fixed Identity Toolkit service account
  // audience, not your project id.
  if (payload && typeof payload.uid === 'string' && typeof payload.aud === 'string' && /^https:\/\/identitytoolkit\.googleapis\.com\//.test(payload.aud)) {
    pushProblem(problems, {
      severity: 'low',
      code: 'firebase_custom_token_not_id_token',
      message: 'This looks like a Firebase custom token (minted server-side by the Admin SDK: has a "uid" claim, aud targets identitytoolkit.googleapis.com), not an ID token. A custom token must be exchanged client-side via signInWithCustomToken() before you get back a verifiable ID token whose iss/aud is https://securetoken.google.com/<project-id>.',
      path: 'payload.uid',
    });
  }
  if (iss && /^https:\/\/securetoken\.google\.com\//.test(iss)) {
    pushProblem(problems, {
      severity: 'info',
      code: 'firebase_id_token_detected',
      message: `iss "${iss}" matches Firebase's ID token issuer pattern (https://securetoken.google.com/<project-id>). Verify it with the project's public keys from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com, selected by the token's "kid" header, and confirm "aud" equals your Firebase project ID exactly.`,
      path: 'payload.iss',
    });
  }
}

// ───────────────────────── diagnose() ─────────────────────────

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function sortProblems(problems) {
  return problems
    .map((p, idx) => ({ p, idx }))
    .sort((a, b) => (SEVERITY_ORDER[a.p.severity] - SEVERITY_ORDER[b.p.severity]) || (a.idx - b.idx))
    .map((x) => x.p);
}

function pushProblem(problems, { severity, code, message, path, value, fix }) {
  problems.push({ severity, code, message, path: path || null, value: value === undefined ? null : value, fix: fix || null, where: path || null });
}

/**
 * @param {object} config
 * @param {string} [config.token] - the raw pasted JWT (or "Bearer <jwt>")
 * @param {{issuer?:string, audience?:string, algorithm?:string, clockSkewSeconds?:number|null}} [config.expected]
 * @param {{type:'none'|'hmac-secret'|'rsa-public-pem'|'jwk', value?:string}} [config.key]
 * @returns {Promise<{status:'pass'|'warn'|'fail', summary:string, expected:object, problems:Array, fixes:Array, checklist:string[], disclaimer:string, decoded:object|null}>}
 */
export async function diagnose(config) {
  const cfg = isPlainObject(config) ? config : {};
  const expectedCfg = isPlainObject(cfg.expected) ? cfg.expected : {};
  const keyCfg = isPlainObject(cfg.key) ? cfg.key : { type: 'none' };

  const problems = [];
  const fixes = [];
  const checklist = [];

  const expected = {
    issuer: safeStr(expectedCfg.issuer).trim() || null,
    audience: safeStr(expectedCfg.audience).trim() || null,
    algorithm: safeStr(expectedCfg.algorithm).trim() || null,
    clockSkewSeconds: typeof expectedCfg.clockSkewSeconds === 'number' && isFinite(expectedCfg.clockSkewSeconds) && expectedCfg.clockSkewSeconds >= 0
      ? expectedCfg.clockSkewSeconds
      : null,
  };
  const skew = expected.clockSkewSeconds == null ? 0 : expected.clockSkewSeconds;

  const rawToken = safeStr(cfg.token);
  let decoded = null;

  if (!rawToken.trim()) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'token_missing',
      message: 'No token was pasted yet. Paste the JWT (the long string with two dots in it) from your Authorization header, cookie, or wherever your app stores it.',
      path: 'token',
    });
    return finish({ status: 'warn', problems, fixes, checklist, expected, decoded });
  }

  const { cleaned, hadBearer, hadQuotes, hadWhitespace } = cleanPastedToken(rawToken);

  if (hadBearer) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'bearer_prefix_present',
      message: 'The pasted value starts with "Bearer " (an HTTP Authorization header prefix, RFC 6750), which is not part of the token itself. It was stripped before decoding below, but make sure your own code never passes the "Bearer " prefix into jwt.verify() / jwtVerify(): that would also produce "jwt malformed".',
      path: 'token',
      value: rawToken.slice(0, 40),
      fix: cleaned,
    });
  }
  if (hadQuotes) {
    pushProblem(problems, {
      severity: 'low',
      code: 'wrapping_quotes_present',
      message: 'The pasted value was wrapped in quote characters (probably copied from a JSON body or .env file). They were stripped before decoding below; if your code reads the token from a JSON field or .env value without parsing it first, the literal quotes end up inside the string and break verification.',
      path: 'token',
      fix: cleaned,
    });
  }
  if (hadWhitespace) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'whitespace_in_token',
      message: 'The pasted value contains whitespace (a space, tab, or line break) inside or around the token. A JWT has no whitespace anywhere: this is usually line-wrapping from a terminal, log line, or copy-paste. It was stripped before decoding below, but the same whitespace in your real code would produce "jwt malformed".',
      path: 'token',
      fix: cleaned,
    });
  }

  const parts = cleaned.split('.');

  if (cleaned.length === 0) {
    pushProblem(problems, { severity: 'high', code: 'jwt_malformed', message: 'Nothing left to decode after removing the Bearer prefix / quotes / whitespace above.', path: 'token' });
    return finish({ status: 'fail', problems, fixes, checklist, expected, decoded });
  }

  if (parts.length !== 3) {
    const extra = parts.length > 3 ? `${parts.length} parts (${parts.length - 1} dots)` : `${parts.length} part${parts.length === 1 ? '' : 's'} (${parts.length - 1} dot${parts.length - 1 === 1 ? '' : 's'})`;
    pushProblem(problems, {
      severity: 'high',
      code: 'jwt_malformed',
      message: `A JWT is three base64url segments separated by exactly two periods (RFC 7515: header.payload.signature). This value has ${extra} instead. This is exactly the condition libraries report as "jwt malformed" (jsonwebtoken) / a JWSInvalid / ERR_JWS_INVALID error (jose).${parts.length === 2 ? ' Two parts with no signature segment usually means the trailing "." before an empty (alg: "none") signature got trimmed off by something along the way, or this is actually a JWE (5 parts) or opaque token, not a JWT at all.' : ''}`,
      path: 'token',
      fix: 'Copy the token again in full: it must contain exactly two "." characters.',
    });
    return finish({ status: 'fail', problems, fixes, checklist, expected, decoded });
  }

  const [headerPart, payloadPart, sigPart] = parts;
  const headerDec = decodeBase64UrlJson(headerPart, 'the header (part 1)');
  const payloadDec = decodeBase64UrlJson(payloadPart, 'the payload (part 2)');

  if (!headerDec.ok) {
    pushProblem(problems, { severity: 'high', code: 'jwt_malformed', message: `Header decode failed: ${headerDec.error}. This is what jsonwebtoken reports as "jwt malformed" / "invalid token".`, path: 'token' });
  }
  if (!payloadDec.ok) {
    pushProblem(problems, { severity: 'high', code: 'jwt_malformed', message: `Payload decode failed: ${payloadDec.error}. This is what jsonwebtoken reports as "jwt malformed" / "invalid token".`, path: 'token' });
  }
  if (!headerDec.ok || !payloadDec.ok) {
    return finish({ status: 'fail', problems, fixes, checklist, expected, decoded });
  }
  if (!isPlainObject(headerDec.value)) {
    pushProblem(problems, { severity: 'high', code: 'jwt_malformed', message: 'The header decoded to valid JSON but it is not a JSON object (RFC 7515 requires a JSON object for the JOSE header).', path: 'token' });
    return finish({ status: 'fail', problems, fixes, checklist, expected, decoded });
  }
  if (!isPlainObject(payloadDec.value)) {
    pushProblem(problems, { severity: 'medium', code: 'payload_not_object', message: 'The payload decoded to valid JSON but it is not a JSON object. RFC 7519 defines the Claims Set as a JSON object; a non-object payload is a valid JWS but not a valid JWT.', path: 'token' });
  }

  const header = headerDec.value;
  const payload = isPlainObject(payloadDec.value) ? payloadDec.value : {};
  decoded = { header, payload, signaturePresent: sigPart.length > 0, raw: { header: headerPart, payload: payloadPart, signature: sigPart } };

  // ── header.alg ───────────────────────────────────────────────────────
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!alg) {
    pushProblem(problems, {
      severity: 'high',
      code: 'alg_missing',
      message: 'header.alg is missing. RFC 7515 requires it: "The alg (algorithm) Header Parameter... MUST be present and MUST be understood and processed by implementations."',
      path: 'header.alg',
    });
  } else if (alg === 'none') {
    pushProblem(problems, {
      severity: 'high',
      code: 'alg_none',
      message: 'header.alg is "none": an Unsecured JWS per RFC 7519 ("with the empty string for its JWS Signature value"). Anyone can forge a token with any payload they want when a verifier accepts "none": this is the classic "alg: none" JWT vulnerability. A verifier must reject this unless it was deliberately built to accept unsecured tokens.' + (sigPart ? ' This token additionally has a non-empty signature segment despite alg being "none", which is itself inconsistent with the unsecured-JWS format.' : ''),
      path: 'header.alg',
      value: 'none',
      fix: 'Sign the token with a real algorithm (e.g. HS256, RS256, ES256), and make sure your verifier has an explicit allow-list of algorithms rather than trusting whatever alg the token claims.',
    });
  }

  if (alg && expected.algorithm && alg !== expected.algorithm) {
    pushProblem(problems, {
      severity: 'high',
      code: 'alg_mismatch',
      message: `header.alg is "${alg}" but you expected "${expected.algorithm}". Signature verification below (if a key was supplied) uses the token's own "${alg}", not your expected value: an attacker-controlled alg is exactly what an "algorithm confusion" attack exploits (e.g. swapping RS256 for HS256 and signing with the RSA public key as if it were an HMAC secret), so a verifier must pin the expected algorithm itself, never read it from the token.`,
      path: 'header.alg',
      value: alg,
      fix: `Configure your verifier to only accept "${expected.algorithm}", and re-issue the token with that algorithm if it currently uses "${alg}".`,
    });
  }

  if (header.kid !== undefined && header.kid !== null && header.kid !== '') {
    pushProblem(problems, {
      severity: 'info',
      code: 'kid_present_no_jwks',
      message: `header.kid is "${String(header.kid)}": the token names a specific signing key rather than assuming there is only one. If you're verifying against a JWKS endpoint (Auth0 /.well-known/jwks.json, Firebase, Cognito, Clerk), fetch the key whose "kid" matches this value. Using the wrong key (e.g. always the first one in the set) is a common source of "invalid signature" after a provider rotates its keys.`,
      path: 'header.kid',
      value: String(header.kid),
    });
  }

  // ── payload.exp / nbf / iat ─────────────────────────────────────────
  const now = nowSeconds();

  if (payload.exp !== undefined) {
    if (!isNumericDate(payload.exp)) {
      pushProblem(problems, { severity: 'medium', code: 'exp_not_numeric', message: 'payload.exp is present but is not a number. RFC 7519 requires "exp" to be a NumericDate (seconds since the Unix epoch, UTC).', path: 'payload.exp', value: payload.exp });
    } else if (now - skew >= payload.exp) {
      pushProblem(problems, {
        severity: 'high',
        code: 'token_expired',
        message: `payload.exp (${fmtTime(payload.exp).iso}) is in the past${skew ? ` even after allowing ${skew}s of clock skew` : ''}. RFC 7519: "the current date/time MUST be before the expiration date/time listed in the 'exp' claim." This is what jsonwebtoken reports as TokenExpiredError ("jwt expired") and jose as JWTExpired (ERR_JWT_EXPIRED). Expired ${relTime(payload.exp, now)}.`,
        path: 'payload.exp',
        value: payload.exp,
        fix: 'Re-issue the token (log in again / refresh), or if this keeps happening right after login, check that the server issuing it and the server verifying it agree on the current time.',
      });
    }
  } else {
    pushProblem(problems, { severity: 'low', code: 'exp_missing', message: 'payload.exp is absent: this token never expires by itself. RFC 7519 does not require "exp", but an access token with no expiry is unusual and worth a second look unless it is intentional (e.g. some refresh tokens, or a long-lived service key).', path: 'payload.exp' });
  }

  if (payload.nbf !== undefined) {
    if (!isNumericDate(payload.nbf)) {
      pushProblem(problems, { severity: 'medium', code: 'nbf_not_numeric', message: 'payload.nbf is present but is not a number (RFC 7519 requires a NumericDate).', path: 'payload.nbf', value: payload.nbf });
    } else if (now + skew < payload.nbf) {
      pushProblem(problems, {
        severity: 'medium',
        code: 'not_yet_valid',
        message: `payload.nbf (${fmtTime(payload.nbf).iso}) is in the future${skew ? ` even after allowing ${skew}s of clock skew` : ''}. RFC 7519: "the current date/time MUST be after or equal to the not-before date/time." jsonwebtoken reports this as NotBeforeError ("jwt not active"). Becomes valid ${relTime(payload.nbf, now)}.`,
        path: 'payload.nbf',
        value: payload.nbf,
        fix: 'Wait until the nbf time passes, or re-issue the token if nbf was set by mistake (e.g. a timezone bug when it was minted).',
      });
    }
  }

  if (payload.iat !== undefined) {
    if (!isNumericDate(payload.iat)) {
      pushProblem(problems, { severity: 'low', code: 'iat_not_numeric', message: 'payload.iat is present but is not a number (RFC 7519 requires a NumericDate).', path: 'payload.iat', value: payload.iat });
    } else if (payload.iat > now + skew) {
      pushProblem(problems, {
        severity: 'low',
        code: 'iat_in_future',
        message: `payload.iat (${fmtTime(payload.iat).iso}) is in the future${skew ? ` even after allowing ${skew}s of clock skew` : ''} (${relTime(payload.iat, now)}). RFC 7519 defines "iat" as "the time at which the JWT was issued" and does not itself require rejecting a future iat, but it usually means the issuing server's clock is ahead of this one: worth checking if exp-based expiry is also behaving oddly.`,
        path: 'payload.iat',
        value: payload.iat,
      });
    }
    if (isNumericDate(payload.exp) && payload.iat > payload.exp) {
      pushProblem(problems, {
        severity: 'medium',
        code: 'iat_after_exp',
        message: `payload.iat (${fmtTime(payload.iat).iso}) is after payload.exp (${fmtTime(payload.exp).iso}): the token claims to have been issued after it already expired. That is internally inconsistent and points at a bug in whatever minted this token (e.g. exp computed from the wrong base time).`,
        path: 'payload.iat',
        value: payload.iat,
      });
    }
  }

  // ── payload.iss / aud ────────────────────────────────────────────────
  if (expected.issuer) {
    const iss = payload.iss;
    if (iss === undefined) {
      pushProblem(problems, { severity: 'medium', code: 'iss_missing', message: `You expected issuer "${expected.issuer}" but payload.iss is absent.`, path: 'payload.iss', fix: `Add "iss": "${expected.issuer}" when the token is issued.` });
    } else if (typeof iss !== 'string' || iss !== expected.issuer) {
      pushProblem(problems, {
        severity: 'high',
        code: 'iss_mismatch',
        message: `payload.iss is "${String(iss)}" but you expected "${expected.issuer}". RFC 7519 defines "iss" as "a case-sensitive string": a single trailing slash or http vs. https difference is enough to fail. jsonwebtoken reports this as "jwt issuer invalid. expected: [${expected.issuer}]"; jose as JWTClaimValidationFailed (ERR_JWT_CLAIM_VALIDATION_FAILED, claim "iss").`,
        path: 'payload.iss',
        value: iss,
        fix: `Either issue the token with "iss": "${expected.issuer}", or update your verifier's expected issuer to "${String(iss)}" if that is actually the correct value.`,
      });
    }
  }

  if (expected.audience) {
    const aud = payload.aud;
    if (aud === undefined) {
      pushProblem(problems, { severity: 'medium', code: 'aud_missing', message: `You expected audience "${expected.audience}" but payload.aud is absent.`, path: 'payload.aud', fix: `Add "aud": "${expected.audience}" when the token is issued.` });
    } else {
      const audList = Array.isArray(aud) ? aud : [aud];
      const allStrings = audList.every((a) => typeof a === 'string');
      if (!allStrings) {
        pushProblem(problems, { severity: 'medium', code: 'aud_invalid_type', message: 'payload.aud is present but is neither a string nor an array of strings. RFC 7519: "the aud value is an array of case-sensitive strings... the aud value MAY be a single case-sensitive string."', path: 'payload.aud', value: aud });
      } else if (!audList.includes(expected.audience)) {
        pushProblem(problems, {
          severity: 'high',
          code: 'aud_mismatch',
          message: `payload.aud is ${JSON.stringify(aud)} but you expected "${expected.audience}" to be in it. RFC 7519: "Each principal intended to process the JWT MUST identify itself with a value in the audience claim... If [it does not], then the JWT MUST be rejected." jsonwebtoken reports this as "jwt audience invalid. expected: [${expected.audience}]"; jose as JWTClaimValidationFailed (ERR_JWT_CLAIM_VALIDATION_FAILED, claim "aud").`,
          path: 'payload.aud',
          value: aud,
          fix: `Either issue the token with "${expected.audience}" included in "aud", or update your verifier's expected audience to match ${JSON.stringify(aud)} if that is actually correct (a very common case: verifying a Supabase/Firebase access token against your own app name instead of the provider's fixed audience value).`,
        });
      }
    }
  }

  // ── signature verification ──────────────────────────────────────────
  let signatureStatus = 'not_checked';
  let signatureNote = null;

  if (alg === 'none') {
    signatureStatus = 'unsigned';
  } else if (!sigPart) {
    pushProblem(problems, {
      severity: 'high',
      code: 'signature_missing',
      message: `header.alg is "${alg}" (a real signing algorithm) but the signature segment (part 3) is empty. jsonwebtoken's jwt.verify() reports this as "jwt signature is required": a non-"none" alg with an empty signature is rejected outright, before even checking the key.`,
      path: 'token',
    });
    signatureStatus = 'missing';
  } else if (keyCfg.type === 'none' || !safeStr(keyCfg.value).trim()) {
    signatureStatus = 'not_checked';
    checklist.push('No verification key was supplied, so the signature itself was not checked: only the token\'s structure and claims were. Paste the HMAC secret or the RSA/EC public key (PEM or JWK) to verify it actually came from who it claims to.');
  } else {
    const kind = algFamily(alg);
    if (kind === 'unknown') {
      pushProblem(problems, { severity: 'medium', code: 'alg_unsupported', message: `"${alg}" is not one of the algorithms this tool can verify (HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512). Verify it with your own library instead.`, path: 'header.alg', value: alg });
      signatureStatus = 'not_checked';
    } else if (kind === 'hmac' && keyCfg.type !== 'hmac-secret') {
      pushProblem(problems, {
        severity: 'high',
        code: 'secret_public_key_mismatch',
        message: `header.alg is "${alg}" (HMAC, a shared secret) but you supplied a ${keyCfg.type === 'jwk' ? 'JWK' : 'PEM public key'}. HMAC verification needs the same secret used to sign, not a public/private keypair: pasting a PEM here for an HS* token cannot work.`,
        path: 'key.type',
        fix: 'Switch the key type to "HMAC secret" and paste the shared secret (e.g. your Supabase project\'s JWT secret from Project Settings → API).',
      });
      signatureStatus = 'not_checked';
    } else if (kind !== 'hmac' && keyCfg.type === 'hmac-secret') {
      pushProblem(problems, {
        severity: 'high',
        code: 'secret_public_key_mismatch',
        message: `header.alg is "${alg}" (asymmetric) but you supplied an HMAC secret. ${alg} tokens are verified with the signer's public key (RSA/EC), never with a shared secret: pasting a secret here for an ${alg} token cannot work, and treating an RSA public key as an HMAC secret (or vice versa) is itself a known "algorithm confusion" attack technique: a verifier must never let the token pick which kind of key it gets checked against.`,
        path: 'key.type',
        fix: `Switch the key type to a public key (PEM or JWK) and paste the ${kind === 'ec' ? 'EC' : 'RSA'} public key that corresponds to whatever signed this token.`,
      });
      signatureStatus = 'not_checked';
    } else if (!keyKindMatchesAlg(keyCfg.type, alg)) {
      pushProblem(problems, { severity: 'medium', code: 'key_alg_mismatch', message: `The supplied key type does not match "${alg}".`, path: 'key.type' });
      signatureStatus = 'not_checked';
    } else if (!cryptoObj) {
      signatureNote = 'Web Crypto (crypto.subtle) is not available in this environment: signature was not checked.';
      signatureStatus = 'not_checked';
    } else {
      const signingInput = `${headerPart}.${payloadPart}`;
      let signatureBytes;
      try {
        signatureBytes = base64UrlToBytes(sigPart);
      } catch (e) {
        pushProblem(problems, { severity: 'high', code: 'signature_not_base64url', message: `The signature segment is not valid base64url: ${e.message}`, path: 'token' });
        signatureStatus = 'error';
        signatureBytes = null;
      }
      if (signatureBytes) {
        try {
          const valid = await verifySignature(alg, keyCfg, signingInput, signatureBytes);
          signatureStatus = valid ? 'valid' : 'invalid';
          if (!valid) {
            pushProblem(problems, {
              severity: 'high',
              code: 'signature_invalid',
              message: `Signature verification failed for "${alg}" against the supplied key. This is exactly what jsonwebtoken reports as "invalid signature" and jose as JWSSignatureVerificationFailed (ERR_JWS_SIGNATURE_VERIFICATION_FAILED). The most common causes, roughly in order: this key does not match the key that actually signed the token (e.g. a rotated secret, or the wrong project's JWT secret pasted in); the token's header or payload was edited/re-encoded after signing (even reformatting whitespace inside the original JSON before encoding changes the signed bytes); or a PEM was pasted with a mismatched header (e.g. a private key, or an "-----BEGIN CERTIFICATE-----" instead of "-----BEGIN PUBLIC KEY-----").`,
              path: 'key.value',
              fix: 'Confirm you copied the exact current secret/key (not a rotated or example one), and that nothing re-encoded the token\'s header/payload after it was signed.',
            });
          }
        } catch (e) {
          signatureStatus = 'error';
          pushProblem(problems, {
            severity: 'medium',
            code: 'signature_check_error',
            message: `Could not run signature verification: ${e.message}. This usually means the pasted key is not in the format the selected key type expects (e.g. a PEM that is not SPKI "-----BEGIN PUBLIC KEY-----", or a JWK missing required fields for this algorithm).`,
            path: 'key.value',
          });
        }
      }
    }
  }

  // ── provider-specific heuristics ────────────────────────────────────
  detectProviderHints(header, payload, problems, pushProblem);

  checklist.push('Decode the token yourself at any point in your own code (jwt.io, or `JSON.parse(Buffer.from(part, "base64url"))`) if a mismatch here is surprising: this tool reads exactly the same three base64url segments your server does.');
  checklist.push('If verification fails only in production, check for a stale environment variable: a rotated secret, an old public key, or an issuer/audience that changed when a project was renamed.');
  if (alg && algFamily(alg) !== 'none') checklist.push(`Pin the accepted algorithm explicitly in your verifier's options (e.g. { algorithms: ["${alg}"] }) rather than trusting header.alg: this is the standard defense against algorithm-confusion attacks.`);

  return finish({ problems, fixes, checklist, expected, decoded, signatureStatus, signatureNote, alg });
}

function finish({ status, problems, fixes, checklist, expected, decoded, signatureStatus, signatureNote, alg }) {
  const sorted = sortProblems(problems);
  const highCount = sorted.filter((p) => p.severity === 'high').length;
  const medCount = sorted.filter((p) => p.severity === 'medium').length;
  const lowCount = sorted.filter((p) => p.severity === 'low').length;

  let finalStatus = status;
  if (!finalStatus) {
    if (highCount > 0) finalStatus = 'fail';
    else if (medCount > 0 || lowCount > 0) finalStatus = 'warn';
    else finalStatus = 'pass';
  }

  let summary;
  if (finalStatus === 'pass') {
    summary = 'No problems found. Structure, timing claims, issuer/audience (where checked), and signature (where a key was supplied) all look correct.';
  } else if (finalStatus === 'fail') {
    const top = sorted.find((p) => p.severity === 'high');
    summary = top
      ? `${highCount} blocking problem${highCount > 1 ? 's' : ''} found. Most urgent: ${top.message}`
      : 'The token could not be fully decoded.';
  } else {
    const top = sorted[0];
    summary = top
      ? `Nothing blocking, but ${medCount + lowCount} thing${medCount + lowCount > 1 ? 's' : ''} worth checking. Top of the list: ${top.message}`
      : 'Nothing to report yet.';
  }

  // Promote a handful of high-value literal fixes (things you'd actually paste) into the fixes[] list.
  const fixesOut = fixes.slice();
  sorted.forEach((p) => {
    if ((p.code === 'bearer_prefix_present' || p.code === 'wrapping_quotes_present' || p.code === 'whitespace_in_token') && p.fix) {
      fixesOut.push({ title: `Cleaned token (${p.code.replace(/_/g, ' ')})`, value: p.fix, where: 'paste this instead' });
    }
    if (p.code === 'http_not_https' && p.fix) fixesOut.push({ title: 'Use https', value: p.fix, where: null });
  });

  return {
    status: finalStatus,
    summary,
    expected,
    problems: sorted,
    fixes: fixesOut,
    checklist,
    disclaimer:
      'Read-only, client-side analysis of the token and values you entered. The token is decoded and, if a key is supplied, its signature is verified entirely in your browser via the Web Crypto API: nothing is sent to a server. Not affiliated with Auth0, Supabase, Firebase, Cognito, Keycloak, Clerk, or any token issuer.',
    decoded,
    signatureStatus: signatureStatus || 'not_checked',
    signatureNote: signatureNote || null,
  };
}

/**
 * Standalone helper: normalizes and returns just the "expected" block
 * diagnose() would use, without decoding a token. Handy for a live preview
 * of what will be checked as the user fills in the form.
 */
export function expectedValues(config) {
  const cfg = isPlainObject(config) ? config : {};
  const e = isPlainObject(cfg.expected) ? cfg.expected : {};
  return {
    issuer: safeStr(e.issuer).trim() || null,
    audience: safeStr(e.audience).trim() || null,
    algorithm: safeStr(e.algorithm).trim() || null,
    clockSkewSeconds: typeof e.clockSkewSeconds === 'number' && isFinite(e.clockSkewSeconds) && e.clockSkewSeconds >= 0 ? e.clockSkewSeconds : null,
  };
}

// Also expose as a plain browser global when loaded via <script type="module">.
if (typeof window !== 'undefined') {
  window.JwtDoctor = { diagnose, expectedValues };
}
