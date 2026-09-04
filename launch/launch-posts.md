# Launch posts — JWT Doctor

Research date: 2026-09-04/06. Tool: https://arling.sk/jwt-doctor/

Method: GitHub REST search API (`api.github.com/search/issues`), repo-scoped issue
listings (`auth0/node-jsonwebtoken`, `panva/jose`), and each repo's own GitHub
Discussions search, for queries built around the exact error strings and
vulnerability classes this tool checks: `"jwt malformed"`, `"invalid
signature"`, `"algorithm confusion"` + jwt, `"jwt audience invalid"`,
`"TokenExpiredError"`, `"JsonWebTokenError"`, `"no matching decryption
secret"`, `verifyIdToken`, Cognito `"invalid signature"` jwt, and clock-skew
/ expiry phrasing. Stack Overflow could not be queried — `stackoverflow.com`
is blocked to this session's fetcher (network restriction on the fetching
tool, not a missing result). Andrej: check manually at
`https://stackoverflow.com/search?q=jwt+malformed&tab=Newest` (and
`invalid+signature`, `TokenExpiredError`) for anything to add.

Every thread named below was actually fetched (including full original-post
text and reply status where a post is recommended); nothing here is
invented. **Rule applied:** closed issue with its last activity more than 12
months ago → skip. A repo's own bug/dependency-scanner reports and internal
task-tracker-style issues (this dataset's GitHub search results are heavily
dominated by these — short imperative titles, all comments from the same
team, filed the same day as "created") → skip, since posting a tool link
into someone's private backlog item reads as spam, not help. Threads that
already carry a solid answer, or already have replies (matching the
precedent set in the Google OAuth Doctor launch research), are skipped too:
a second reply there adds nothing.

---

## 1. Findings

### 1.1 Broad searches: exact error strings, sorted by updated

As with the OAuth-redirect research before it, current GitHub issue search
results for these exact strings are dominated by: automated dependency
vulnerability scanners (`"jsonwebtoken-8.5.1.tgz: N vulnerabilities"`,
`opentok/insights-dashboard-sample#74`, `Nexmo/ni-node-async-tutorial#1`,
`nexmo-community/google-cloud-sample-code#20`); single-team internal
task/roadmap issues (`Sky-Teams/Mizban-Delivery-backend#136`,
`mbelinkie/vera-research-video-clips#7`,
`jmg887/databuilder#1`); and PRs, not questions
(`neuraflow-github/my-traefik-jwt-plugin#5`,
`ThalesGroup/fred#2542`). All of these are **skip**.

A handful looked promising and were checked in full:

| Thread | State | Recommendation |
|---|---|---|
| [istio/istio#60326](https://github.com/istio/istio/issues/60326) — pilot-agent presents an expired JWT for 22+ hours | open | Skip — internal infra bug with the reporter's own root-cause analysis already attached (an internal service's credential-refresh logic), not a case this tool's "paste and check a token" flow addresses. |
| [trinodb/trino#21512](https://github.com/trinodb/trino/issues/21512) — workers stuck reporting "JWT expired... ago" | open, 44 comments | Skip — verified in full: root cause identified and worked around (`thread-per-driver-scheduler-enabled: false`); a thread-pool bug, not a token-content question. |
| [tazama-lf/biar#161](https://github.com/tazama-lf/biar/issues/161) — "algorithm-confusion attack in place" | open | Skip — the repo's own maintainer describing and fixing a bug in their own code (`algorithms=["RS256"]` pinning), not a public question. |
| [safetrustcr/dApp-SafeTrust#359](https://github.com/safetrustcr/dApp-SafeTrust/issues/359) — migrate sync-user with Firebase Admin verification | open | Skip — internal refactor ticket assigned within the team's own board. |
| [Infisical/infisical#7823](https://github.com/Infisical/infisical/issues/7823) — expired JWT returns 403 instead of 401, breaking silent refresh | open, 5 comments | Skip — a bug in Infisical's own frontend interceptor logic (checks only 401), not a case where a pasted-token diagnostic helps; already has maintainer engagement. |
| [supabase/ssr#107](https://github.com/supabase/ssr/issues/107) — `AuthSessionMissingError` despite a valid cookie | open (stale label), 4 comments | Skip — verified in full: this is a cookie/session-plumbing bug in `@supabase/ssr` (the session cookie never reaches `getUser()`), not a malformed/expired/mis-signed JWT — outside what this tool diagnoses. |

### 1.2 GitHub Discussions — `panva/jose`

| Discussion | Status | Posted | Recommendation |
|---|---|---|---|
| [#834 — "How to catch an expired JWT on verify?"](https://github.com/panva/jose/discussions/834) | answered, 1 reply | 2025-12-04 | Skip — verified in full: chrislyons-dev's reply (2026-01-01) already gives a complete, correct answer (`JWTExpired` / `ERR_JWT_EXPIRED`, with a working code example). A second reply adds nothing. |
| [#836 — "Compute exp according to iat"](https://github.com/panva/jose/discussions/836) | idea, 1 reply | 2025-12-28 | Skip — a feature-request/design discussion aimed at the maintainer, not a spot for a third-party tool link. |

### 1.3 GitHub Discussions — `nextauthjs/next-auth`

| Discussion | Status | Posted | Recommendation |
|---|---|---|---|
| [#12527 — "How do I decode a JWT string using the `decode` function from `next-auth/jwt`?"](https://github.com/nextauthjs/next-auth/discussions/12527) | **unanswered**, 0 replies | 2025-01-22 | **Post** (see §2.1). Verified in full: chrisidakwo gets `"no matching decryption secret"` calling `decode()` directly with values that work fine through `getToken()`. Genuinely unanswered after ~19 months, and it's a real, diagnosable JWT-handling bug this tool's domain knowledge (JWE vs. JWS) directly explains. |
| [#12633 — "Using next-auth session token in node and express"](https://github.com/nextauthjs/next-auth/discussions/12633) | unanswered, 1 reply | 2025-02-09 | Skip — verified in full: already has a correct community reply explaining the JWE-vs-JWS distinction (the exact same root cause as #12527). A second reply there would just restate it. |
| [#4255 — "Need help in resolving 'Invalid Compact JWE' error"](https://github.com/nextauthjs/next-auth/discussions/4255) | unanswered, 30 replies | 2022-03-24 | Skip — 30 replies already; whatever this tool could add is almost certainly already in that thread. |
| [#6642 — "JWT Token refresh - getting outdated token to JWT callback"](https://github.com/nextauthjs/next-auth/discussions/6642) | unanswered, 93 replies | 2023-02-07 | Skip — huge existing thread; about refresh-token flow design, not a token this tool would diagnose. |
| [#9133 — "What to use as salt when calling getToken()?"](https://github.com/nextauthjs/next-auth/discussions/9133) | unanswered, 11 replies | 2023-11-13 | Skip — already has 11 replies covering the salt/cookie-name question directly. |
| [#5685 — "Backend JWE Decryption / Validation"](https://github.com/nextauthjs/next-auth/discussions/5685) | unanswered, 1 reply | 2022-10-31 | Skip — old (2022), and the same JWE-decryption territory as #12527/#12633 above; posting into three near-duplicate threads is spam, not help — #12527 is the one with zero replies and the clearest reproducible bug. |

### 1.4 `auth0/node-jsonwebtoken` issues

The repo's own open-issue list (checked directly, not via search) is almost
entirely maintainer-facing: dependency-CVE requests (#1023, #991), type
edge cases (#1042, #757), runtime-compatibility bugs (#992, #980, #939,
#885), and a real ReDoS/security report (#1031, #1021, #1019) that are
squarely for the library's own maintainers to fix, not places to drop a
downstream tool link. The handful of "jwt malformed"-titled issues
(#591, #652, #837, #882, #333, #871, #768, #379, #415) are all closed and
2017–2023, several years past the 12-month cutoff. **All skip.**

**Stack Overflow:** blocked to this session's fetcher — see Method above.
Andrej: worth a manual pass, since "jwt malformed" / "invalid signature" /
"jwt expired" are exactly the kind of question that lives there rather than
in GitHub Issues.

---

## 2. Drafted reply (first person, as Andrej)

Post this only if the thread is still open for replies. Ends with exactly
one sentence pointing at the tool.

### 2.1 → https://github.com/nextauthjs/next-auth/discussions/12527

> Hey — the short version: NextAuth/Auth.js's own session token (the one in the `next-auth.session-token` / `authjs.session-token` cookie) usually isn't a signed JWT at all. By default it's a JWE (encrypted, `"dir"` key management + `A256CBC-HS512`), which is why calling `decode()` on it directly behaves differently than you'd expect from a plain signed JWT.
>
> The specific error, `"no matching decryption secret"`, comes out of key derivation: the JWE's actual encryption key isn't just your `secret`, it's `HKDF-SHA256(secret, salt, "Auth.js Generated Encryption Key (" + salt + ")", ...)`, and `salt` defaults to the exact session cookie name — `next-auth.session-token` in dev, `__Secure-next-auth.session-token` once you're on HTTPS in production (or the `authjs.*` names if you're on v5/Auth.js). `getToken()` works because it resolves that cookie name internally before calling `decode()` for you; a standalone `decode()` call needs you to pass the *matching* `salt` yourself, and dev-vs-prod (or v4-vs-v5 cookie naming) is the single most common way that quietly drifts out of sync.
>
> For the actual goal here (third-party bearer-token auth): rather than fighting to decrypt NextAuth's own internal session artifact from outside NextAuth, the usual pattern is to mint a separate, real signed JWT (a plain JWS — HS256 or RS256, with your own `iss`/`aud`/`exp`) purpose-built for external API consumption, and verify *that* with a standard verifier instead of trying to peel apart the session cookie's JWE.
>
> If you go that route, I built a free tool that decodes a JWT's header/claims and verifies its signature against a pasted secret or public key, handy for confirming a token you've minted is actually well-formed before wiring up the receiving side: https://arling.sk/jwt-doctor/

---

## 3. Facts for Andrej's own post

1. Free JWT decoder and diagnostic: paste a token, get the header and payload decoded and checked against every relevant RFC 7519 / RFC 7515 rule in one pass.
2. Verifies signatures for 9 algorithms natively via the browser's own WebCrypto: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.
3. 100% client-side, no backend at all: the token, secret, and key never leave the browser, verifiable by reading the two static files (`index.html`, `doctor-jwt.js`) or the network tab.
4. Auto-cleans the three most common copy-paste mistakes before decoding anything: a leftover `Bearer ` prefix, wrapping quotes, and embedded whitespace — each still reported, not silently ignored.
5. Specifically flags the RS256→HS256 "algorithm confusion" attack shape (a secret pasted where a public key belongs, or the reverse) — the single most-cited real-world JWT signature vulnerability class.
6. Recognizes provider-specific token shapes by their payload structure: a Supabase project API key vs. a user's access token, and a Firebase custom token vs. an already-exchanged ID token.
7. Every rule cites its source in `llms-full.txt`: RFC 7519 (JWT), RFC 7515 (JWS), and the actual error strings/codes thrown by `jsonwebtoken` and `jose`, so the tool's wording matches what developers already see in their own stack traces.
8. Built and shipped in a single day on zero budget, no CDN dependencies, responsive from 360px wide — the newest member of the ARLing "Doctor" family (Google OAuth redirect, Supabase redirect on web/Expo/Flutter, Stripe webhook signatures).

---

## 4. Show HN

**Title:** Show HN: A free JWT decoder that also verifies the signature, all client-side

**Body:**

> Hi HN — every JWT debugging session I've had eventually comes down to one of a handful of things: the token isn't actually 3 parts (a stray `Bearer ` prefix or wrapping quotes got pasted in too), `alg` is `none`, `exp`/`nbf` don't line up with clock skew, `iss`/`aud` don't match what the verifier expects, or the signature itself just doesn't check out against the key you think signed it. jwt.io decodes the token, but doesn't check any of that against your actual values, and doesn't verify RS256/ES256 signatures against a public key at all.
>
> I built a small tool for it: paste a JWT (with or without `Bearer `, quotes, stray whitespace — all cleaned up automatically) and optionally the secret or public key it should be signed with, and it decodes the header/payload, runs every RFC 7519/7515 rule against it, and verifies the signature with the browser's own WebCrypto (`crypto.subtle`) — HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.
>
> It also flags the classic RS256→HS256 "algorithm confusion" attack shape specifically (pasting a public key where a secret belongs, or vice versa) — genuinely the most-cited real-world JWT signature bug, and one I've made myself more than once.
>
> Entirely client-side — one HTML file, one dependency-free JS file, no backend, no account, nothing you paste ever leaves your browser (check the network tab, or just read the source, it's static files).
>
> Free, no ads, source is on GitHub. Would love feedback, especially on token shapes or algorithms it doesn't cover yet.
>
> https://arling.sk/jwt-doctor/

---

## 5. Reddit / Discord / forums

Generic English text — this is a global developer tool, not a Slovak or
accounting-domain product, so there's no Slovak-forum variant this time.
Post to r/webdev, r/node, r/reactnative (Expo/RN auth threads), r/aws
(Cognito), and the Auth0 / NextAuth / Supabase Discord servers' help
channels — **check each community's self-promotion rules before posting**
(several subreddits require a "Sunday self-promo thread" or flair).

> **Built a free JWT decoder that also verifies the signature (HS256/RS256/ES256), all client-side**
>
> If you've ever stared at a JWT that "should" work and gotten a useless error back — `jwt malformed`, `invalid signature`, `jwt expired` — I made a small free tool: paste the token (with or without `Bearer `, quotes, stray whitespace, all cleaned up automatically) and optionally the secret/public key it should be signed with, and it decodes the header/claims, checks every timing/issuer/audience rule, and verifies the actual signature using the browser's own WebCrypto — no backend, nothing you paste leaves your browser.
>
> Covers HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, and flags the classic "pasted a public key where a secret belongs" (or the reverse) algorithm-confusion mistake specifically.
>
> https://arling.sk/jwt-doctor/
>
> (Not selling anything, just a tool I wished existed the last few times I hit this.)

---

## 6. Article outline (dev.to)

**Working title:** *Six things that actually break a JWT, and how to tell which one*

1. **The hook** — the library's own error (`jwt malformed`, `invalid signature`, `jwt expired`) tells you the symptom, not the cause; here are the actual causes, ranked by how often each one is it.
2. **What a JWT actually is** — RFC 7515 §7.1's Compact Serialization: `BASE64URL(header) || '.' || BASE64URL(payload) || '.' || BASE64URL(signature)`, exactly two dots, no whitespace, no padding (RFC 7515 §2). Cite: `datatracker.ietf.org/doc/html/rfc7515`.
3. **The six real-world causes, one snippet each:**
   - A paste artifact masquerading as "malformed": a `Bearer ` prefix, wrapping quotes, or embedded whitespace.
   - `alg: none` — an Unsecured JWT per RFC 7519 §6, and what trusting it actually means.
   - Algorithm confusion — RS256 re-signed as HS256 using the server's own public key as the "secret."
   - `exp`/`nbf` vs. clock skew (RFC 7519 §4.1.4–§4.1.5) — and the classic seconds-vs-milliseconds `exp` bug.
   - `iss`/`aud` mismatch — RFC 7519 §4.1.1/§4.1.3, including the "verifying against your own app name instead of the provider's fixed audience" Supabase/Firebase gotcha.
   - Signature mismatch after a rotated secret, or after the header/payload got re-encoded (even just reformatted) post-signing.
4. **Provider-specific gotchas** — a Supabase project API key vs. a user access token; a Firebase custom token vs. an ID token; NextAuth/Auth.js's own session cookie being a JWE (`A256CBC-HS512`), not a JWS, which is why `jwt.verify()` on it throws `jwt malformed` outright.
5. **A checklist you can run by hand** — or the free tool that automates the byte-diff and the signature check (link at the end, not before).
6. **Sources** — RFC 7519, RFC 7515, `jsonwebtoken`'s error docs, `jose`'s error classes — link each one cited in the piece.
