# JWT Doctor

A free tool that decodes a JSON Web Token, tells you exactly what's wrong with it (malformed structure, `alg: none`, algorithm mismatch, expired or not-yet-valid, wrong issuer or audience), and verifies its signature against a pasted secret or public key.

Live: https://arling.sk/jwt-doctor/

You paste a JWT (with or without a `Bearer ` prefix, quotes, or stray whitespace, all detected and stripped automatically) and, optionally, the secret or public key it should have been signed with. The tool decodes the header and payload, runs every structural and claim check the JOSE/JWT specs define, verifies the signature with the browser's own WebCrypto API when a key is supplied, and reports the precise problem plus a copy-paste fix.

## What it checks

Each check below is a `code` the engine (`doctor-jwt.js`) can return from `diagnose()`:

**Paste artifacts** (stripped before decoding, each still flagged): `bearer_prefix_present`, `wrapping_quotes_present`, `whitespace_in_token`.

**Structure**: `jwt_malformed` (not three dot-separated base64url parts, or a part isn't valid JSON), `payload_not_object`.

**Header**: `alg_missing`, `alg_none` (RFC 7519 §6 Unsecured JWT, the signature-stripping vulnerability class), `alg_mismatch` (header `alg` doesn't match what you expected, the algorithm-confusion attack surface), `kid_present_no_jwks` (informational).

**Timing claims**: `token_expired` (`exp` in the past, with an adjustable clock-skew tolerance), `exp_missing`, `not_yet_valid` (`nbf` in the future), `iat_in_future` (low severity, a clock-skew hint), `iat_after_exp`, plus `exp_not_numeric` / `nbf_not_numeric` / `iat_not_numeric`.

**Issuer / audience**: `iss_mismatch`, `iss_missing`, `aud_mismatch` (RFC 7519 allows `aud` as a string or an array; both forms are checked), `aud_missing`, `aud_invalid_type`.

**Signature**, verified with native WebCrypto (`crypto.subtle`), never a reimplementation: `signature_missing`, `secret_public_key_mismatch` (an HS* algorithm with a pasted PEM/JWK, or an RS*/PS*/ES* algorithm with a pasted plain secret: the shape of the RS256→HS256 algorithm-confusion attack), `alg_unsupported`, `key_alg_mismatch`, `signature_not_base64url`, `signature_check_error`, `signature_invalid`.

**Provider-shape heuristics** (pattern-matched from the decoded payload, no network call): `supabase_project_key_not_user_token` (a Supabase project API key pasted where a user access token was expected), `firebase_custom_token_not_id_token` (an unexchanged Firebase custom token), `firebase_id_token_detected` (points at the right Google public-key endpoint).

Algorithms supported for signature verification: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512 (verified in raw JOSE `r‖s` form, as every JWT library produces, not DER).

## What it does not do

- It does not call your identity provider, a JWKS endpoint, or any live API. Signature verification runs against the key you paste in, not one fetched over the network.
- It does not decrypt JWEs (encrypted tokens): only JWS-based JWTs (the vast majority of access/ID tokens in the wild).
- It does not send, store, or log your token, secret, or key anywhere. There is no account, no login, and no payment wall.
- It does not know about token shapes or providers it hasn't been told about, or about spec changes since this was last updated (see Sources below).

## How it works

Everything runs in your browser. `doctor-jwt.js`, one dependency-free JavaScript file, exports a single async pure function, `diagnose(config)`, which the page calls with the token and values you fill in and renders the result as a plain-language report. Nothing about your token, secret, or key is sent anywhere; the only network activity is loading the page's own static assets and anonymous Umami analytics events (see Privacy).

```js
import { diagnose } from './doctor-jwt.js';

const result = await diagnose({
  token: rawPastedToken, // with or without "Bearer ", quotes, whitespace
  expected: {
    issuer: 'https://auth.example.com/',
    audience: 'api://example',
    algorithm: 'RS256',
    clockSkewSeconds: 60,
  },
  key: {
    type: 'rsa-public-pem', // 'none' | 'hmac-secret' | 'rsa-public-pem' | 'jwk'
    value: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  },
});
```

Output (illustrative, RS256 header checked against a pasted HMAC secret by mistake):

```json
{
  "status": "fail",
  "summary": "1 blocking problem found. Most urgent: header.alg is \"RS256\" (asymmetric) but you supplied an HMAC secret...",
  "problems": [
    {
      "severity": "high",
      "code": "secret_public_key_mismatch",
      "message": "header.alg is \"RS256\" (asymmetric) but you supplied an HMAC secret. RS256 tokens are verified with the signer's public key (RSA/EC), never with a shared secret...",
      "path": "key.type",
      "fix": "Switch the key type to a public key (PEM or JWK) and paste the RSA public key that corresponds to whatever signed this token."
    }
  ],
  "signatureStatus": "not_checked",
  "disclaimer": "Read-only, client-side analysis of the token and values you entered. Not affiliated with Auth0, Supabase, Firebase, Cognito, Keycloak, Clerk, or any token issuer."
}
```

Nothing else about that token is wrong: it's well-formed and unexpired, with correct `iss`/`aud`. The pasted key was just the wrong kind, which `diagnose()` catches before it even attempts a (meaningless) HMAC verify against an RSA public key.

## Run locally

No build step, no dependencies.

```bash
git clone https://github.com/AndryRoby/jwt-doctor.git
cd jwt-doctor
python -m http.server
# or just open index.html directly in a browser
```

## Tests

```bash
node tests.mjs
```

104 assertions, 104 passed, 0 failed as of this writing.

## Privacy

Everything runs client-side; nothing you paste into the form (token, secret, or key) is sent anywhere, ever. Product analytics (page views, "run check" clicked) go to a self-hosted Umami instance with no cookies and no personal data, event name and count only. Joining the "tell me about new tools" email list on the page is entirely optional and separate from using the tool. Full policy: https://arling.sk/privacy/.

## Sources

The rules this tool checks are drawn from:

- IETF: [RFC 7519, JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- IETF: [RFC 7515, JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- `auth0/node-jsonwebtoken`: [error messages and codes](https://github.com/auth0/node-jsonwebtoken#errors)
- `panva/jose`: [error classes](https://github.com/panva/jose)

## Report a problem

Found a JWT bug this tool doesn't catch, or a check that flags something that's actually fine? Open an issue: https://github.com/AndryRoby/jwt-doctor/issues, or write to andrej@arling.sk. Please redact real tokens, secrets, and keys before posting; issues are public.

## License

All rights reserved, see [LICENSE-NOTICE.md](LICENSE-NOTICE.md). Reading the source and learning from it is fine; deploying your own copy of it as a competing product is not.

---

ARLing s. r. o., Bratislava, Slovakia. andrej@arling.sk

Hub (more free tools): https://arling.sk/

Sibling tools:
- Google OAuth redirect_uri_mismatch: https://arling.sk/google-oauth-redirect-doctor/
- Supabase Auth on the web (Next.js / Vite / SvelteKit): https://arling.sk/supabase-redirect-doctor/
- Supabase Auth on Expo / React Native: https://arling.sk/expo-supabase-auth-doctor/
- Supabase Auth on Flutter: https://arling.sk/flutter-supabase-doctor/
- Stripe webhook signature verification: https://arling.sk/stripe-webhook-doctor/
- SEPA pain.001 for Slovak banks: https://arling.sk/sepa-pain001-doctor/
- BookApp: https://arling.sk/bookapp/
