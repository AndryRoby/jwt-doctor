// tests.mjs — plain Node test runner for doctor-jwt.js (no external
// dependencies beyond Node's own built-in node:crypto, used only to mint
// test tokens; doctor-jwt.js itself never imports node:crypto — it verifies
// signatures through the same globalThis.crypto.subtle Web Crypto API a
// browser exposes, which Node 19+ also provides).
// Run with: node tests.mjs

import crypto from 'node:crypto';
import { diagnose, expectedValues } from './doctor-jwt.js';

let pass = 0;
let fail = 0;
const failures = [];

function ok(name, cond, detail) {
  if (cond) {
    pass++;
  } else {
    fail++;
    failures.push(`${name}${detail ? ' — ' + detail : ''}`);
  }
}

function eq(name, actual, expected) {
  const condition = actual === expected;
  ok(name, condition, condition ? '' : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function has(name, arr, code) {
  const condition = Array.isArray(arr) && arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `expected a problem with code "${code}", got codes [${(arr || []).map((p) => p.code).join(', ')}]`);
}

function lacks(name, arr, code) {
  const condition = Array.isArray(arr) && !arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `did not expect a problem with code "${code}"`);
}

function severityOf(arr, code) {
  const p = (arr || []).find((x) => x.code === code);
  return p ? p.severity : undefined;
}

// ── token-building helpers (test fixtures only) ────────────────────────
function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function signingInputOf(header, payload) {
  return `${b64urlJson(header)}.${b64urlJson(payload)}`;
}

function hmacToken(header, payload, secret) {
  const input = signingInputOf(header, payload);
  const algo = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }[header.alg] || 'sha256';
  const sig = crypto.createHmac(algo, secret).update(input).digest();
  return `${input}.${sig.toString('base64url')}`;
}

function rsaKeyPair(modulusLength = 2048) {
  return crypto.generateKeyPairSync('rsa', { modulusLength });
}

function rsaToken(header, payload, privateKey) {
  const input = signingInputOf(header, payload);
  const algo = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512' }[header.alg] || 'sha256';
  const sig = crypto.sign(algo, Buffer.from(input, 'utf8'), privateKey);
  return `${input}.${sig.toString('base64url')}`;
}

function ecKeyPair(namedCurve = 'P-256') {
  return crypto.generateKeyPairSync('ec', { namedCurve });
}

function ecToken(header, payload, privateKey) {
  const input = signingInputOf(header, payload);
  const algo = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' }[header.alg] || 'sha256';
  const sig = crypto.sign(algo, Buffer.from(input, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

function pssToken(header, payload, privateKey) {
  const input = signingInputOf(header, payload);
  const algo = { PS256: 'sha256', PS384: 'sha384', PS512: 'sha512' }[header.alg] || 'sha256';
  const saltLength = { PS256: 32, PS384: 48, PS512: 64 }[header.alg] || 32;
  const sig = crypto.sign(algo, Buffer.from(input, 'utf8'), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength,
  });
  return `${input}.${sig.toString('base64url')}`;
}

function pemOf(key) {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

function jwkOf(key) {
  return JSON.stringify(key.export({ format: 'jwk' }));
}

const NOW = Math.floor(Date.now() / 1000);

async function main() {
  // ─────────────────────────────────────────────────────────────────────
  // 1. Structural / RFC 7515 compact-serialization checks
  // ─────────────────────────────────────────────────────────────────────

  {
    const r = await diagnose({ token: '' });
    eq('empty token -> status warn', r.status, 'warn');
    has('empty token -> token_missing', r.problems, 'token_missing');
  }
  {
    const r = await diagnose({ token: '   ' });
    eq('whitespace-only token -> status warn', r.status, 'warn');
    has('whitespace-only token -> token_missing', r.problems, 'token_missing');
  }
  {
    const r = await diagnose({ token: 'not-a-jwt-at-all' });
    eq('one part, no dots -> status fail', r.status, 'fail');
    has('one part -> jwt_malformed', r.problems, 'jwt_malformed');
  }
  {
    const r = await diagnose({ token: 'abc.def' });
    eq('two parts -> status fail', r.status, 'fail');
    has('two parts -> jwt_malformed', r.problems, 'jwt_malformed');
  }
  {
    const r = await diagnose({ token: 'a.b.c.d' });
    has('four parts -> jwt_malformed', r.problems, 'jwt_malformed');
  }
  {
    const r = await diagnose({ token: '"   "' });
    has('quoted whitespace -> jwt_malformed after cleanup', r.problems, 'jwt_malformed');
  }
  {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token: `Bearer ${token}` });
    has('Bearer prefix detected', r.problems, 'bearer_prefix_present');
    eq('Bearer prefix severity', severityOf(r.problems, 'bearer_prefix_present'), 'medium');
    ok('Bearer prefix stripped before decode (header still parses)', r.decoded && r.decoded.header.alg === 'HS256');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token: `"${token}"` });
    has('wrapping quotes detected', r.problems, 'wrapping_quotes_present');
    eq('wrapping quotes severity', severityOf(r.problems, 'wrapping_quotes_present'), 'low');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const wrapped = token.slice(0, 20) + '\n' + token.slice(20);
    const r = await diagnose({ token: wrapped });
    has('internal whitespace/newline detected', r.problems, 'whitespace_in_token');
    ok('whitespace-wrapped token still decodes header after cleanup', r.decoded && r.decoded.header.alg === 'HS256');
  }
  {
    const bad = `${Buffer.from('not json', 'utf8').toString('base64url')}.${b64urlJson({ sub: '1' })}.sig`;
    const r = await diagnose({ token: bad });
    has('non-JSON header -> jwt_malformed', r.problems, 'jwt_malformed');
    eq('non-JSON header -> status fail', r.status, 'fail');
  }
  {
    const bad = `${b64urlJson({ alg: 'HS256' })}.not!!valid!!base64url.sig`;
    const r = await diagnose({ token: bad });
    has('invalid base64url payload -> jwt_malformed', r.problems, 'jwt_malformed');
  }
  {
    const bad = `${b64urlJson([1, 2, 3])}.${b64urlJson({ sub: '1' })}.sig`;
    const r = await diagnose({ token: bad });
    has('header is a JSON array, not object -> jwt_malformed', r.problems, 'jwt_malformed');
  }
  {
    const bad = `${b64urlJson({ alg: 'HS256' })}.${b64urlJson([1, 2, 3])}.sig`;
    const r = await diagnose({ token: bad });
    has('payload is a JSON array, not object -> payload_not_object', r.problems, 'payload_not_object');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 2. header.alg checks
  // ─────────────────────────────────────────────────────────────────────

  {
    const token = `${b64urlJson({ typ: 'JWT' })}.${b64urlJson({ sub: '1' })}.`;
    const r = await diagnose({ token });
    has('missing alg -> alg_missing', r.problems, 'alg_missing');
    eq('missing alg severity', severityOf(r.problems, 'alg_missing'), 'high');
  }
  {
    const token = `${b64urlJson({ alg: 'none' })}.${b64urlJson({ sub: '1', admin: true })}.`;
    const r = await diagnose({ token });
    has('alg none -> alg_none', r.problems, 'alg_none');
    eq('alg none severity', severityOf(r.problems, 'alg_none'), 'high');
    eq('alg none -> status fail', r.status, 'fail');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { algorithm: 'RS256' } });
    has('alg mismatch vs expected -> alg_mismatch', r.problems, 'alg_mismatch');
    eq('alg mismatch severity', severityOf(r.problems, 'alg_mismatch'), 'high');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { algorithm: 'HS256' } });
    lacks('matching alg -> no alg_mismatch', r.problems, 'alg_mismatch');
  }
  {
    const header = { alg: 'HS256', kid: 'key-1' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('kid present -> kid_present_no_jwks', r.problems, 'kid_present_no_jwks');
    eq('kid info severity does not affect status', severityOf(r.problems, 'kid_present_no_jwks'), 'info');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 3. exp / nbf / iat
  // ─────────────────────────────────────────────────────────────────────

  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW - 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('expired token -> token_expired', r.problems, 'token_expired');
    eq('expired token severity', severityOf(r.problems, 'token_expired'), 'high');
    eq('expired token -> status fail', r.status, 'fail');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW - 30 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { clockSkewSeconds: 300 } });
    lacks('expired 30s ago but within 300s clock skew -> no token_expired', r.problems, 'token_expired');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW - 600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { clockSkewSeconds: 60 } });
    has('expired 600s ago exceeds 60s clock skew -> token_expired', r.problems, 'token_expired');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('no exp claim -> exp_missing', r.problems, 'exp_missing');
    eq('exp_missing severity', severityOf(r.problems, 'exp_missing'), 'low');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: 'soon' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('non-numeric exp -> exp_not_numeric', r.problems, 'exp_not_numeric');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600, nbf: NOW + 1800 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('future nbf -> not_yet_valid', r.problems, 'not_yet_valid');
    eq('not_yet_valid severity', severityOf(r.problems, 'not_yet_valid'), 'medium');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600, nbf: NOW + 30 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { clockSkewSeconds: 300 } });
    lacks('future nbf within clock skew -> no not_yet_valid', r.problems, 'not_yet_valid');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600, iat: NOW + 1800 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('future iat -> iat_in_future', r.problems, 'iat_in_future');
    eq('iat_in_future severity', severityOf(r.problems, 'iat_in_future'), 'low');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', iat: NOW, exp: NOW - 10 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('iat after exp -> iat_after_exp', r.problems, 'iat_after_exp');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 4. iss / aud
  // ─────────────────────────────────────────────────────────────────────

  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', iss: 'https://issuer.example.com' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { issuer: 'https://issuer.example.com/' } });
    has('iss trailing-slash mismatch -> iss_mismatch', r.problems, 'iss_mismatch');
    eq('iss_mismatch severity', severityOf(r.problems, 'iss_mismatch'), 'high');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', iss: 'https://issuer.example.com' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { issuer: 'https://issuer.example.com' } });
    lacks('matching iss -> no iss_mismatch', r.problems, 'iss_mismatch');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { issuer: 'https://issuer.example.com' } });
    has('missing iss when expected -> iss_missing', r.problems, 'iss_missing');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', aud: 'other-app' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { audience: 'my-app' } });
    has('aud string mismatch -> aud_mismatch', r.problems, 'aud_mismatch');
    eq('aud_mismatch severity', severityOf(r.problems, 'aud_mismatch'), 'high');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', aud: ['my-app', 'other-app'] };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { audience: 'my-app' } });
    lacks('aud array containing expected -> no aud_mismatch', r.problems, 'aud_mismatch');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', aud: 42 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { audience: 'my-app' } });
    has('aud wrong type -> aud_invalid_type', r.problems, 'aud_invalid_type');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, expected: { audience: 'my-app' } });
    has('missing aud when expected -> aud_missing', r.problems, 'aud_missing');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 5. Signature verification: HMAC
  // ─────────────────────────────────────────────────────────────────────

  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'correct-secret');
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 'correct-secret' } });
    eq('HS256 correct secret -> signatureStatus valid', r.signatureStatus, 'valid');
    lacks('HS256 correct secret -> no signature_invalid', r.problems, 'signature_invalid');
    eq('HS256 correct secret, no other issues -> status pass', r.status, 'pass');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'correct-secret');
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 'wrong-secret' } });
    eq('HS256 wrong secret -> signatureStatus invalid', r.signatureStatus, 'invalid');
    has('HS256 wrong secret -> signature_invalid', r.problems, 'signature_invalid');
    eq('signature_invalid severity', severityOf(r.problems, 'signature_invalid'), 'high');
    eq('HS256 wrong secret -> status fail', r.status, 'fail');
  }
  {
    const header = { alg: 'HS384' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 's');
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 's' } });
    eq('HS384 correct secret -> valid', r.signatureStatus, 'valid');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    eq('no key supplied -> signatureStatus not_checked', r.signatureStatus, 'not_checked');
    lacks('no key supplied -> no signature_invalid', r.problems, 'signature_invalid');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 6. Signature verification: RSA (RS256) — PEM and JWK
  // ─────────────────────────────────────────────────────────────────────

  {
    const { publicKey, privateKey } = rsaKeyPair();
    const header = { alg: 'RS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('RS256 correct public key (PEM) -> valid', r.signatureStatus, 'valid');
    eq('RS256 correct key, nothing else wrong -> status pass', r.status, 'pass');
  }
  {
    const { publicKey } = rsaKeyPair();
    const { privateKey: otherPrivate } = rsaKeyPair();
    const header = { alg: 'RS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = rsaToken(header, payload, otherPrivate);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('RS256 wrong public key -> invalid', r.signatureStatus, 'invalid');
    has('RS256 wrong public key -> signature_invalid', r.problems, 'signature_invalid');
  }
  {
    const { publicKey, privateKey } = rsaKeyPair();
    const header = { alg: 'RS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'jwk', value: jwkOf(publicKey) } });
    eq('RS256 correct public key (JWK) -> valid', r.signatureStatus, 'valid');
  }
  {
    const { publicKey, privateKey } = rsaKeyPair();
    const header = { alg: 'RS384' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('RS384 correct public key -> valid', r.signatureStatus, 'valid');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 6b. Signature verification: RSA-PSS (PS256)
  // ─────────────────────────────────────────────────────────────────────

  {
    const { publicKey, privateKey } = rsaKeyPair();
    const header = { alg: 'PS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = pssToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('PS256 correct public key (PEM) -> valid', r.signatureStatus, 'valid');
    eq('PS256 correct key, nothing else wrong -> status pass', r.status, 'pass');
  }
  {
    const { publicKey } = rsaKeyPair();
    const { privateKey: otherPrivate } = rsaKeyPair();
    const header = { alg: 'PS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = pssToken(header, payload, otherPrivate);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('PS256 wrong public key -> invalid', r.signatureStatus, 'invalid');
    has('PS256 wrong public key -> signature_invalid', r.problems, 'signature_invalid');
  }
  {
    const { publicKey, privateKey } = rsaKeyPair();
    const header = { alg: 'PS384' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = pssToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'jwk', value: jwkOf(publicKey) } });
    eq('PS384 correct public key (JWK) -> valid', r.signatureStatus, 'valid');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 7. Signature verification: ECDSA (ES256)
  // ─────────────────────────────────────────────────────────────────────

  {
    const { publicKey, privateKey } = ecKeyPair('P-256');
    const header = { alg: 'ES256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = ecToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('ES256 correct public key (PEM) -> valid', r.signatureStatus, 'valid');
  }
  {
    const { publicKey } = ecKeyPair('P-256');
    const { privateKey: otherPrivate } = ecKeyPair('P-256');
    const header = { alg: 'ES256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = ecToken(header, payload, otherPrivate);
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    eq('ES256 wrong public key -> invalid', r.signatureStatus, 'invalid');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 8. Secret vs. public-key confusion (algorithm-confusion guard)
  // ─────────────────────────────────────────────────────────────────────

  {
    const { publicKey } = rsaKeyPair();
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, key: { type: 'rsa-public-pem', value: pemOf(publicKey) } });
    has('HS256 token + PEM key -> secret_public_key_mismatch', r.problems, 'secret_public_key_mismatch');
    eq('secret_public_key_mismatch severity', severityOf(r.problems, 'secret_public_key_mismatch'), 'high');
    eq('HS256 + PEM -> signatureStatus not_checked', r.signatureStatus, 'not_checked');
  }
  {
    const { privateKey } = rsaKeyPair();
    const header = { alg: 'RS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 'some-secret' } });
    has('RS256 token + HMAC secret -> secret_public_key_mismatch', r.problems, 'secret_public_key_mismatch');
    eq('RS256 + secret -> signatureStatus not_checked', r.signatureStatus, 'not_checked');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 'secret' } });
    lacks('matching HMAC key type -> no secret_public_key_mismatch', r.problems, 'secret_public_key_mismatch');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 9. alg: "none" + non-empty signature, and empty signature on a real alg
  // ─────────────────────────────────────────────────────────────────────

  {
    const token = `${b64urlJson({ alg: 'HS256' })}.${b64urlJson({ sub: '1', exp: NOW + 3600 })}.`;
    const r = await diagnose({ token });
    has('real alg with empty signature -> signature_missing', r.problems, 'signature_missing');
    eq('signature_missing severity', severityOf(r.problems, 'signature_missing'), 'high');
  }
  {
    const token = `${b64urlJson({ alg: 'none' })}.${b64urlJson({ sub: '1', admin: true })}.deadbeef`;
    const r = await diagnose({ token });
    has('alg none with non-empty signature still flags alg_none', r.problems, 'alg_none');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 10. Provider-specific heuristics (Supabase / Firebase)
  // ─────────────────────────────────────────────────────────────────────

  {
    const header = { alg: 'HS256' };
    const payload = { role: 'anon', iss: 'supabase', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    has('Supabase anon key shape -> supabase_project_key_not_user_token', r.problems, 'supabase_project_key_not_user_token');
    eq('supabase hint severity', severityOf(r.problems, 'supabase_project_key_not_user_token'), 'low');
  }
  {
    const header = { alg: 'HS256' };
    const payload = { role: 'authenticated', sub: 'user-1', exp: NOW + 3600 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token });
    lacks('authenticated role with sub -> no supabase key hint', r.problems, 'supabase_project_key_not_user_token');
  }
  {
    const header = { alg: 'RS256' };
    const payload = { uid: 'user-1', aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit' };
    const { privateKey } = rsaKeyPair();
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token });
    has('Firebase custom token shape -> firebase_custom_token_not_id_token', r.problems, 'firebase_custom_token_not_id_token');
  }
  {
    const header = { alg: 'RS256', kid: 'abc' };
    const payload = { iss: 'https://securetoken.google.com/my-project', aud: 'my-project', sub: 'user-1', exp: NOW + 3600 };
    const { privateKey } = rsaKeyPair();
    const token = rsaToken(header, payload, privateKey);
    const r = await diagnose({ token });
    has('Firebase ID token iss -> firebase_id_token_detected', r.problems, 'firebase_id_token_detected');
    eq('firebase id token hint is info severity', severityOf(r.problems, 'firebase_id_token_detected'), 'info');
  }

  // ─────────────────────────────────────────────────────────────────────
  // 11. expectedValues() normalization helper
  // ─────────────────────────────────────────────────────────────────────

  eq('expectedValues: trims issuer', expectedValues({ expected: { issuer: '  https://issuer.example.com  ' } }).issuer, 'https://issuer.example.com');
  eq('expectedValues: empty audience -> null', expectedValues({ expected: { audience: '' } }).audience, null);
  eq('expectedValues: negative clockSkewSeconds -> null', expectedValues({ expected: { clockSkewSeconds: -5 } }).clockSkewSeconds, null);
  eq('expectedValues: valid clockSkewSeconds kept', expectedValues({ expected: { clockSkewSeconds: 120 } }).clockSkewSeconds, 120);
  eq('expectedValues: no config -> all null', JSON.stringify(expectedValues({})), JSON.stringify({ issuer: null, audience: null, algorithm: null, clockSkewSeconds: null }));

  // ─────────────────────────────────────────────────────────────────────
  // 12. Overall status roll-up
  // ─────────────────────────────────────────────────────────────────────

  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1', iss: 'https://issuer.example.com', aud: 'my-app', exp: NOW + 3600, iat: NOW - 10 };
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({
      token,
      expected: { issuer: 'https://issuer.example.com', audience: 'my-app', algorithm: 'HS256', clockSkewSeconds: 30 },
      key: { type: 'hmac-secret', value: 'secret' },
    });
    eq('fully valid token -> status pass', r.status, 'pass');
    eq('fully valid token -> 0 problems', r.problems.length, 0);
    ok('checklist is non-empty even on pass', Array.isArray(r.checklist) && r.checklist.length > 0);
  }
  {
    const header = { alg: 'HS256' };
    const payload = { sub: '1' }; // no exp at all -> only a "low" problem
    const token = hmacToken(header, payload, 'secret');
    const r = await diagnose({ token, key: { type: 'hmac-secret', value: 'secret' } });
    eq('only low-severity findings -> status warn', r.status, 'warn');
  }
  {
    const r = await diagnose({});
    eq('no config at all -> status warn (token_missing)', r.status, 'warn');
  }
  {
    const r = await diagnose(null);
    eq('null config does not throw -> status warn', r.status, 'warn');
  }

  // ── summary ──────────────────────────────────────────────────────────
  console.log(`\n${pass} passed, ${fail} failed, ${pass + fail} total.`);
  if (fail > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(' - ' + f);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error('Test runner crashed:', e);
  process.exitCode = 1;
});
