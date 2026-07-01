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

## Scope — JVM Clojure only

**This implementation targets JVM Clojure (`.clj`) only.** X25519 Diffie-Hellman
uses `java.security`/`javax.crypto`'s built-in "X25519"/"XDH" support (JDK 11+);
there is no pure-Clojure/CLJS X25519 in the kotoba-lang dependency graph, and
hand-rolling one is out of scope for correctness reasons (see "Why JVM-only"
below). **CJS / browser / babashka are NOT supported** — do not `:require` this
from a `.cljc` file expecting cross-platform behavior. A CJS-capable X25519 (via
a vetted pure-JS/WASM implementation, e.g. something noble-curves-equivalent)
is a legitimate follow-up but is explicitly deferred.

Also out of scope (follow-up work, not implemented here):
- **Key revocation / rotation policy** for SPKs and group sender-keys (the
  primitives to rotate exist; a scheduler/policy for *when* does not).
- **Group membership management** (add/remove members, access control) — the
  sender-keys chain ratchet itself is implemented, membership bookkeeping is not.
- **Skipped-message-key cache** for out-of-order/dropped-message recovery in
  both the Double Ratchet and the group ratchet — both assume in-order
  delivery within a chain (see the scope notes in `ratchet.clj` / `group.clj`).
- **Header encryption** (Signal's optional "sealed sender"-adjacent header
  protection) — ratchet headers (`{:dh-pub :n}`) are sent in the clear here.

## Why JVM-only, why HKDF is hand-rolled, why not XEdDSA

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
  hkdf.clj      RFC 5869 HKDF-SHA256 (extract / expand), from scratch
  x25519.clj    raw 32-byte X25519 DH via JCA (JVM XDH provider)
  x3dh.clj      X3DH key agreement (identity/prekey bundles, initiate/respond)
  ratchet.clj   Double Ratchet (root KDF, chain KDF, AES-256-GCM messages)
  group.clj     sender-keys group ratchet (distribution, sender/member derive)
test/kotoba/signal/
  hkdf_test.clj     RFC 5869 §A.1–A.3 vectors, byte-for-byte
  x3dh_test.clj     bundle signature verify/reject, initiate↔respond round-trip
  ratchet_test.clj  forward secrecy, message-key uniqueness, full session
  group_test.clj    distribution auth, sender/member lockstep, chain forward secrecy
```

## Usage

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

## Correctness

`clojure -M:test` → **23 tests / 62 assertions, 0 failures, 0 errors**:
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

## License

Apache-2.0.
