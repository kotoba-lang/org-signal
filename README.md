# kotoba-signal

[![CI](https://github.com/kotoba-lang/kotoba-signal/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/kotoba-signal/actions/workflows/ci.yml)

**Signal-style E2E encryption in Clojure: X3DH key agreement + Double Ratchet +
a sender-keys group ratchet.** This is the CLJC/EDN-first re-implementation of
what used to be the Rust `kotoba-signal` crate in `kotoba-lang/kotoba` (removed
in PR #259 — see `docs/rust-crate-migration.md` there). It's the "Signal E2E"
half of `kotoba-lang/kotoba`'s stated authorization model ("CACAO (depth-2
delegation) + Signal E2E (X3DH → Double Ratchet, group)") and is the key
distribution primitive ADR `2606271500-kotoba-stage-obs-live-aozora` points at
for private live-streaming: a broadcaster ratchets a chain key forward once per
media segment, and every viewer bootstrapped into the group derives that
segment's key without a fresh per-segment DH round.

## Scope — two backends, JVM (sync) + CLJS (async), no `.cljc` sharing

**JVM Clojure (`.clj`) and ClojureScript (`.cljs`) are both supported, as
separate sibling implementations, not one shared `.cljc`.** The original
"CJS not supported" call (below, kept for history) turned out to be about the
*JVM's* dependency graph having no X25519, not CJS lacking one — app-aozora
(a browser messenger) needed exactly this ratchet and already had a working,
tested `@noble/curves`-based X25519/AES-GCM implementation (audited, no native
bindings, runs in browsers/Workers/Node), so `x25519.cljs`/`hkdf.cljs`/
`ratchet.cljs` port the JVM files' algorithms and state shapes 1:1 using that.

They are genuinely separate files, not `#?(:clj :cljs)` branches in one
`.cljc`, because **Web Crypto has no synchronous API** — every JVM function
here (`dh`, `hkdf`, `kdf-chain-key`, `ratchet-encrypt`, ...) returns a plain
value; every CLJS one returns a `Promise` of the same value. Forcing both
into one file would mean either making the JVM side needlessly async or
giving CLJS callers a fake-sync API — neither is worth it for the amount of
logic actually shared (the algorithms, not the code).

**Porting gotcha that would NOT have shown up in the JVM test suite:** the JVM
`decrypt-message` compares `(:dh-remote state)` against an incoming header's
`:dh-pub` with plain `=`, which for `byte[]` is *reference* equality in
Clojure — harmless there only because the JVM tests keep everything as live,
non-serialized data (the same array object flows unchanged through the pure
functions). The CLJS port's tests deliberately round-trip every envelope
through `JSON.stringify`/`atob`/`btoa` (simulating the real wire), which
exposed that a naive line-for-line translation would DH-ratchet on every
single message once real serialization is involved. `ratchet.cljs` fixes this
with a `bytes=` byte-content comparison instead — see its ns docstring and
`ratchet_test.cljs`'s `full-session-roundtrip-both-directions-over-the-wire`.

CLJS-only dev tooling (`shadow-cljs.edn`, `package.json`, the `:cljs-test`
deps.edn alias) is test/build infrastructure only, not part of what JVM
consumers pull in via `:local/root` (JVM `:paths` is still just `["src"]`,
untouched).

`group.cljs` now exists (app-aozora's messenger added group chat, needing the
sender-keys ratchet) — it's mostly glue over `ratchet.cljs`'s already-ported
`kdf-chain-key`/`ratchet-encrypt`/`ratchet-decrypt`, plus Ed25519 sign/verify.
One deliberate difference from the JVM version: `:sig-pub` here is a raw
Ed25519 public key, not a `did:key` string (see `group.cljs`'s ns docstring —
this package doesn't need a did:key encoder for what that signature actually
proves).

X3DH (`x3dh.clj`) and CACAO identity binding remain **JVM-only for now** —
app-aozora's messenger uses X3DH-lite (identity key + signed prekey, no
one-time-prekeys; see `yoro-ui.interop.signal` there) rather than this
package's full X3DH, so porting `x3dh.cljs` is deferred until a consumer
actually needs it, not implemented speculatively.

Also out of scope (follow-up work, not implemented here, both backends):
- **Key revocation / rotation policy** for SPKs and group sender-keys (the
  primitives to rotate exist; a scheduler/policy for *when* does not).
- **Group membership management** (add/remove members, access control) — the
  sender-keys chain ratchet itself is implemented, membership bookkeeping is not.
- **Skipped-message-key cache** for out-of-order/dropped-message recovery in
  both the Double Ratchet and the group ratchet — both assume in-order
  delivery within a chain (see the scope notes in `ratchet.clj` / `group.clj`).
- **Header encryption** (Signal's optional "sealed sender"-adjacent header
  protection) — ratchet headers (`{:dh-pub :n}`) are sent in the clear here.

## Why the JVM backend is built the way it is (HKDF hand-rolled, no XEdDSA)

- **X25519 / AES-256-GCM**: use the JDK's own `java.security`/`javax.crypto`
  ("X25519" KeyAgreement, "AES/GCM/NoPadding" Cipher) rather than reimplementing
  field arithmetic — these are exactly the primitives audited crypto providers
  ship, and reimplementing them "for portability" is how subtle timing/branch
  bugs get introduced. `src/kotoba/signal/x25519.clj` only adds the thin
  PKCS8/X.509 DER wrapping so raw 32-byte keys can travel in EDN maps, using
  the same technique `com-junkawasaki/ed25519-clj` already established for
  Ed25519 (identical minimal key encoding, different OID byte:
  X25519 = `1.3.101.110`, Ed25519 = `1.3.101.112`).
- **HKDF (RFC 5869)** has no JDK built-in (only the raw HMAC primitive it's
  built from), so `src/kotoba/signal/hkdf.clj` implements it directly on
  `javax.crypto.Mac`("HmacSHA256") and is pinned against **all three** RFC 5869
  Appendix A test vectors (basic, longer inputs/outputs, zero-length
  salt/info), independently cross-checked against a from-scratch Python
  `hmac`/`hashlib` computation before being committed.
- **No XEdDSA**: "real" Signal reuses ONE Curve25519 keypair for both DH (X3DH)
  and signing (Ed25519, via the birational XEdDSA curve conversion), so an
  identity has a single key. This implementation instead gives an identity a
  *separate* X25519 keypair (`:ik`, DH only) and Ed25519 seed (`:sign-seed`,
  signing only) — two independent, directly-JCA-supported primitives instead
  of one curve-converted one. The SPK is still identity-bound (its signature
  is checked in `verify-bundle`), which is XEdDSA's actual job in the spec;
  X3DH's core secrecy property (both sides derive the identical shared secret
  from independent DH computations) is unaffected, and is exactly what
  `x3dh_test.clj`'s round-trip test checks.

## Layout

```
src/kotoba/signal/
  hkdf.clj       RFC 5869 HKDF-SHA256 (extract / expand), from scratch — JVM/sync
  hkdf.cljs      same algorithm, Web Crypto — CLJS/async (Promise)
  x25519.clj     raw 32-byte X25519 DH via JCA (JVM XDH provider) — JVM/sync
  x25519.cljs    raw 32-byte X25519 DH via @noble/curves — CLJS/sync (no Promise needed)
  x3dh.clj       X3DH key agreement (identity/prekey bundles, initiate/respond) — JVM only, no CLJS port yet
  ratchet.clj    Double Ratchet (root KDF, chain KDF, AES-256-GCM messages) — JVM/sync
  ratchet.cljs   same state shape/algorithm — CLJS/async, + a bytes= content-equality
                 fix a naive port would have missed (see ns docstring)
  group.clj      sender-keys group ratchet (distribution, sender/member derive) — JVM/sync
  group.cljs     same shape — CLJS/async, mostly glue over ratchet.cljs + Ed25519 sign/verify
test/kotoba/signal/
  hkdf_test.clj(s)     RFC 5869 §A.1–A.3 vectors, byte-for-byte, both backends
  x3dh_test.clj        bundle signature verify/reject, initiate↔respond round-trip (JVM only)
  ratchet_test.clj(s)  forward secrecy, message-key uniqueness, full session, both
                        backends; the CLJS suite additionally round-trips every
                        envelope through JSON/base64 (simulating the wire) and
                        has a dedicated post-compromise-security healing test
  group_test.clj(s)    distribution auth, sender/member lockstep, chain forward secrecy, both backends
```

## Usage — JVM (sync)

```clojure
(require '[kotoba.signal.x3dh :as x3dh]
         '[kotoba.signal.ratchet :as ratchet])

;; --- X3DH: Bob publishes a bundle, Alice initiates against it ---
(def bob (x3dh/generate-identity))
(def alice (x3dh/generate-identity))
(let [[bundle _bob'] (x3dh/publish-bundle bob)]
  (assert (x3dh/verify-bundle bundle))            ; ALWAYS verify before initiating
  (let [{:keys [shared-secret ek-pub opk-id]} (x3dh/x3dh-initiate alice bundle)
        bob-secret (x3dh/x3dh-respond bob (:pub (:ik alice)) ek-pub opk-id)]
    (assert (= (seq shared-secret) (seq bob-secret)))

    ;; --- Double Ratchet, bootstrapped from the X3DH secret ---
    (let [a (ratchet/init-sender shared-secret (:pub (:spk bob)))
          b (ratchet/init-receiver shared-secret (:spk bob))
          [a1 env1] (ratchet/encrypt-message a (.getBytes "hi bob" "UTF-8"))
          [_b1 pt1] (ratchet/decrypt-message b env1)]
      (String. ^bytes pt1 "UTF-8"))))               ;=> "hi bob"
```

## Usage — CLJS (async)

No `x3dh.cljs` yet (see Scope) — bring your own session-establishment secret
(X3DH-lite, a simpler ECDH, whatever fits) and bootstrap the ratchet from it:

```clojure
(require '[kotoba.signal.ratchet :as ratchet])

(-> (js/Promise.all #js [(ratchet/init-sender shared-secret bobs-initial-dh-pub)
                         (ratchet/init-receiver shared-secret bobs-initial-dh-keypair)])
    (.then (fn [^js pair] (ratchet/encrypt-message (aget pair 0) (utf8 "hi bob"))))
    (.then (fn [[alice1 env1]] (ratchet/decrypt-message bob env1)))
    (.then (fn [[_bob1 pt1]] (js/console.log (utf8-decode pt1)))))  ;=> "hi bob"
```

Group (sender-keys) — one chain per sender, distributed pairwise (e.g. over
the same 1:1 session above) to every member:

```clojure
(require '[kotoba.signal.group :as group])

(def sender-key (group/create-sender-key))
(def dist (group/distribution-message sender-key 0))  ; send this to each member
(assert (group/verify-distribution dist))              ; member checks first

(-> (js/Promise.all #js [(group/sender-advance sender-key)
                         (group/member-derive (:chain-key dist))])
    (.then (fn [^js pair]
             (let [[_sk1 sender-mk] (aget pair 0)
                   [_ck1 member-mk] (aget pair 1)]
               (-> (group/encrypt-segment sender-mk (utf8 "group message"))
                   (.then (fn [env] (group/decrypt-segment member-mk env)))
                   (.then (fn [pt] (js/console.log (utf8-decode pt)))))))))  ;=> "group message"
```

## Correctness

**JVM** — `clojure -M:test` → **23 tests / 62 assertions, 0 failures, 0 errors**:
- HKDF pinned against all 3 RFC 5869 test vectors (extract + expand + combined).
- X3DH: SPK-signature verify/reject, initiate↔respond shared-secret round-trip
  (with and without an OPK), distinct sessions ⇒ distinct secrets, OPK pool
  single-use consumption.
- Double Ratchet: chain-key forward secrecy (each step's outputs differ and
  the KDF is one-way HMAC), message-key uniqueness across 200 chain steps,
  AES-GCM encrypt/decrypt round-trip + tamper rejection, fresh IV per call,
  full bidirectional session (DH ratchet turns both ways).
- Group (sender-keys): distribution-message signature verify/reject, sender
  and member independently derive identical message keys in lockstep, 50-step
  chain forward secrecy, a member without a valid distribution cannot forge
  agreement with the sender's chain.

**CLJS** — `pnpm install && pnpm exec shadow-cljs compile test && node out/node-tests.js`
→ **16 tests / 31 assertions, 0 failures, 0 errors**:
- Same HKDF RFC 5869 vectors, same chain-key forward secrecy / message-key
  uniqueness / AES-GCM round-trip+tamper properties as the JVM suite.
- Full bidirectional session round trip with every envelope going through an
  actual `JSON.stringify`/base64 round trip (not live in-memory objects) —
  this is what caught the `bytes=` porting gotcha (see Scope).
- Post-compromise-security healing: an attacker who steals the current
  send-chain state loses the thread the instant either side performs a fresh
  DH turn, since the new root key needs a private key they never held.
- Group (sender-keys): same properties as the JVM suite — distribution
  verify/reject, sender/member lockstep agreement, 50-step forward secrecy,
  a member without a valid distribution can't forge agreement.

## License

Apache-2.0.
