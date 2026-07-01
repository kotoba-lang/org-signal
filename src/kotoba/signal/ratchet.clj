;; kotoba.signal.ratchet — Double Ratchet (Marlinspike & Perrin, "The Double
;; Ratchet Algorithm", 2016): a DH ratchet (fresh X25519 keypair per direction
;; turn) driving a symmetric-key ratchet (HMAC chain) per message, encrypting
;; with AES-256-GCM (javax.crypto). Built on kotoba.signal.x25519 (DH) and
;; kotoba.signal.hkdf (root-key KDF).
;;
;; SCOPE NOTE: no skipped-message-key store — this assumes in-order delivery
;; within a chain (a dropped/reordered message on the CURRENT chain cannot be
;; decrypted later). Signal's real client-side ratchet keeps a bounded cache of
;; skipped message keys for exactly this case; that's a delivery-robustness
;; feature orthogonal to the core ratchet math and is left out of scope (see
;; README "Not implemented").
;;
;;   (require '[kotoba.signal.ratchet :as ratchet])
;;   (ratchet/kdf-root-key root-key dh-out)    ;=> {:root-key :chain-key}
;;   (ratchet/kdf-chain-key chain-key)         ;=> {:chain-key :message-key}
;;   (ratchet/ratchet-encrypt message-key pt)  ;=> {:iv :ciphertext}
;;   (ratchet/ratchet-decrypt message-key env) ;=> plaintext bytes
;;   ;; full session, after X3DH produced `shared-secret`:
;;   (def alice (ratchet/init-sender shared-secret bobs-initial-dh-pub))
;;   (def bob   (ratchet/init-receiver shared-secret bobs-initial-dh-keypair))
;;   (let [[alice' env] (ratchet/encrypt-message alice "hi")]
;;     (ratchet/decrypt-message bob env))      ;=> [bob' "hi"]
(ns kotoba.signal.ratchet
  (:require [kotoba.signal.x25519 :as dh]
            [kotoba.signal.hkdf :as hkdf])
  (:import (java.security SecureRandom)
           (javax.crypto Cipher Mac)
           (javax.crypto.spec SecretKeySpec GCMParameterSpec)))

;; ── KDFs (Double Ratchet spec §5.2) ────────────────────────────────────────────
(def ^:private root-kdf-info (.getBytes "kotoba-signal DR root" "UTF-8"))
(def ^:private chain-const-msg   (byte-array [(unchecked-byte 0x01)]))
(def ^:private chain-const-chain (byte-array [(unchecked-byte 0x02)]))

(defn- hmac-sha256 ^bytes [^bytes key ^bytes data]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. key "HmacSHA256"))
    (.doFinal mac data)))

(defn kdf-root-key
  "Root KDF: (root-key, DH output) -> {:root-key bytes32 :chain-key bytes32}.
   HKDF over the DH output, keyed/salted by the current root key (RFC 5869 via
   kotoba.signal.hkdf), split into a fresh root key + a fresh chain key. Called
   on every DH ratchet turn."
  [^bytes root-key ^bytes dh-out]
  (let [okm (hkdf/hkdf root-key dh-out root-kdf-info 64)]
    {:root-key (byte-array (take 32 okm))
     :chain-key (byte-array (drop 32 okm))}))

(defn kdf-chain-key
  "Chain KDF: chain-key -> {:chain-key bytes32 :message-key bytes32}, via two
   HMACs of the SAME chain key under different constant inputs (Signal's
   #5.2 scheme): message-key = HMAC(ck, 0x01), next chain-key = HMAC(ck, 0x02).
   One-way: HMAC is not invertible, so neither the message-key nor the next
   chain-key can be used to recover this chain-key (forward secrecy per step —
   see ratchet_test.clj `chain-key-forward-secrecy`)."
  [^bytes chain-key]
  {:message-key (hmac-sha256 chain-key chain-const-msg)
   :chain-key (hmac-sha256 chain-key chain-const-chain)})

;; ── AES-256-GCM message encryption ────────────────────────────────────────────
(defn- gcm-cipher ^Cipher [^long mode ^bytes key ^bytes iv]
  (doto (Cipher/getInstance "AES/GCM/NoPadding")
    (.init (int mode) (SecretKeySpec. key "AES") (GCMParameterSpec. 128 iv))))

(defn ratchet-encrypt
  "message-key (32 raw bytes, used directly as the AES-256 key) + plaintext (+
   optional AAD) -> {:iv bytes12 :ciphertext bytes} via AES-256-GCM with a fresh
   random 96-bit IV. Message keys are ONE-SHOT by construction — every message
   gets its own key from `kdf-chain-key`, so IV/key reuse across messages never
   happens (see ratchet_test.clj `message-key-uniqueness`)."
  ([message-key plaintext] (ratchet-encrypt message-key plaintext (byte-array 0)))
  ([^bytes message-key ^bytes plaintext ^bytes aad]
   (let [iv (byte-array 12)
         _ (.nextBytes (SecureRandom.) iv)
         c (gcm-cipher Cipher/ENCRYPT_MODE message-key iv)]
     (when (pos? (alength aad)) (.updateAAD c aad))
     {:iv iv :ciphertext (.doFinal c plaintext)})))

(defn ratchet-decrypt
  "Inverse of `ratchet-encrypt`. Throws (AEADBadTagException) on tamper/wrong key."
  (^bytes [message-key envelope] (ratchet-decrypt message-key envelope (byte-array 0)))
  ([^bytes message-key {:keys [^bytes iv ^bytes ciphertext]} ^bytes aad]
   (let [c (gcm-cipher Cipher/DECRYPT_MODE message-key iv)]
     (when (pos? (alength aad)) (.updateAAD c aad))
     (.doFinal c ciphertext))))

;; ── full session (DH ratchet + per-message symmetric ratchet) ────────────────
(defn init-sender
  "Alice's side: `shared-secret` from X3DH + Bob's current ratchet pubkey
   (conventionally his SPK pub, reused as the bootstrap DR key so no extra
   round-trip is needed before the first message). Alice immediately generates
   her own first ratchet keypair and derives a send-chain from it."
  [^bytes shared-secret their-initial-dh-pub]
  (let [my-dh (dh/generate-keypair)
        dh-out (dh/dh (:priv my-dh) their-initial-dh-pub)
        {:keys [root-key chain-key]} (kdf-root-key shared-secret dh-out)]
    {:dh-priv (:priv my-dh) :dh-pub (:pub my-dh) :dh-remote their-initial-dh-pub
     :root-key root-key
     :send-chain-key chain-key :send-chain-remote their-initial-dh-pub
     :recv-chain-key nil :recv-chain-remote nil
     :send-n 0 :recv-n 0}))

(defn init-receiver
  "Bob's side: `shared-secret` from X3DH (same value Alice has) + the keypair
   whose PUBLIC half Alice used as `their-initial-dh-pub` in `init-sender`
   (typically Bob's SPK keypair). Bob has no send-chain yet — he only gets one
   once Alice's first message tells him her ratchet pubkey (see `encrypt-message`,
   which auto-ratchets the sender side forward when :dh-remote has moved)."
  [^bytes shared-secret my-initial-dh-keypair]
  {:dh-priv (:priv my-initial-dh-keypair) :dh-pub (:pub my-initial-dh-keypair) :dh-remote nil
   :root-key shared-secret
   :send-chain-key nil :send-chain-remote nil
   :recv-chain-key nil :recv-chain-remote nil
   :send-n 0 :recv-n 0})

(defn- dh-ratchet-recv
  "Receiving a message with a NEW peer ratchet pubkey: DH-ratchet the root key
   forward and derive a fresh receiving chain from it."
  [state their-new-dh-pub]
  (let [dh-out (dh/dh (:dh-priv state) their-new-dh-pub)
        {:keys [root-key chain-key]} (kdf-root-key (:root-key state) dh-out)]
    (assoc state :dh-remote their-new-dh-pub :root-key root-key
           :recv-chain-key chain-key :recv-chain-remote their-new-dh-pub :recv-n 0)))

(defn- dh-ratchet-send
  "About to send after the peer's ratchet pubkey moved: generate a NEW own
   ratchet keypair, DH-ratchet the root key forward, derive a fresh sending
   chain from it."
  [state]
  (let [my-dh (dh/generate-keypair)
        dh-out (dh/dh (:priv my-dh) (:dh-remote state))
        {:keys [root-key chain-key]} (kdf-root-key (:root-key state) dh-out)]
    (assoc state :dh-priv (:priv my-dh) :dh-pub (:pub my-dh)
           :root-key root-key :send-chain-key chain-key :send-n 0)))

(defn encrypt-message
  "Advance the sending chain by one message, DH-ratcheting first if the peer's
   ratchet pubkey has moved since the send-chain was last (re)derived. Returns
   [new-state {:header {:dh-pub :n} :iv :ciphertext}] — :header MUST travel
   with the ciphertext so the receiver can follow the same ratchet."
  [state plaintext]
  (let [state (if (and (:dh-remote state) (not= (:send-chain-remote state) (:dh-remote state)))
                (-> (dh-ratchet-send state) (assoc :send-chain-remote (:dh-remote state)))
                state)
        {:keys [chain-key message-key]} (kdf-chain-key (:send-chain-key state))
        env (ratchet-encrypt message-key plaintext)
        header {:dh-pub (:dh-pub state) :n (:send-n state)}]
    [(-> state (assoc :send-chain-key chain-key) (update :send-n inc))
     (assoc env :header header)]))

(defn decrypt-message
  "Advance the receiving chain by one message, DH-ratcheting first if the
   sender's header :dh-pub is new. Returns [new-state plaintext].
   NOTE: assumes in-order, non-dropped delivery within a chain (see ns scope note)."
  [state {:keys [header] :as envelope}]
  (let [state (if (= (:dh-remote state) (:dh-pub header))
                state
                (dh-ratchet-recv state (:dh-pub header)))
        {:keys [chain-key message-key]} (kdf-chain-key (:recv-chain-key state))
        pt (ratchet-decrypt message-key envelope)]
    [(-> state (assoc :recv-chain-key chain-key) (update :recv-n inc)) pt]))
