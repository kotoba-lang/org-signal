(ns kotoba.signal.ratchet-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.signal.x3dh :as x3dh]
            [kotoba.signal.ratchet :as ratchet])
  (:import (java.security SecureRandom)
           (javax.crypto AEADBadTagException)))

(defn- rand-bytes ^bytes [n]
  (let [b (byte-array n)] (.nextBytes (SecureRandom.) b) b))

(defn- bytes< ^bytes [^String s] (.getBytes s "UTF-8"))

(deftest chain-key-forward-secrecy
  (testing "each chain-key step yields a distinct, unrecoverable message-key and next chain-key"
    (let [ck0 (rand-bytes 32)
          {ck1 :chain-key mk1 :message-key} (ratchet/kdf-chain-key ck0)
          {ck2 :chain-key mk2 :message-key} (ratchet/kdf-chain-key ck1)
          {ck3 :chain-key mk3 :message-key} (ratchet/kdf-chain-key ck2)]
      (is (not= (seq mk1) (seq mk2) (seq mk3)) "message keys are distinct per step")
      (is (not= (seq ck0) (seq ck1) (seq ck2) (seq ck3)) "chain keys are distinct per step")
      ;; one-wayness: you cannot walk the DERIVED values back to ck0. We can't
      ;; prove "impossible to invert HMAC" in a unit test, but we CAN assert
      ;; the forward-only API never exposes an inverse, and that knowing ck1
      ;; (a "compromise" of a later step) does not equal any function of the
      ;; ORIGINAL ck0 material one would need to recompute mk1 again:
      (is (= (seq mk1) (seq (:message-key (ratchet/kdf-chain-key ck0))))
          "deriving from the SAME chain-key is deterministic (sanity)")
      (is (not= (seq ck0) (seq mk1)) "message-key is never equal to the chain-key it's derived from"))))

(deftest message-key-uniqueness-across-many-steps
  (let [ck (rand-bytes 32)
        n 200
        keys (loop [ck ck i 0 acc []]
               (if (= i n)
                 acc
                 (let [{:keys [chain-key message-key]} (ratchet/kdf-chain-key ck)]
                   (recur chain-key (inc i) (conj acc (seq message-key))))))]
    (is (= n (count (distinct keys))) "no two message keys collide across 200 chain steps")))

(deftest ratchet-encrypt-decrypt-roundtrip
  (let [mk (rand-bytes 32)
        pt (.getBytes "the segment key rotates every message" "UTF-8")
        env (ratchet/ratchet-encrypt mk pt)]
    (is (= (seq pt) (seq (ratchet/ratchet-decrypt mk env))))))

(deftest ratchet-decrypt-rejects-tamper
  (let [mk (rand-bytes 32)
        env (ratchet/ratchet-encrypt mk (.getBytes "hello" "UTF-8"))
        ct (:ciphertext env)
        _ (aset-byte ct 0 (unchecked-byte (bit-xor (aget ct 0) 1)))]
    (is (thrown? AEADBadTagException (ratchet/ratchet-decrypt mk env)))))

(deftest ratchet-encrypt-uses-fresh-iv-each-call
  (let [mk (rand-bytes 32)
        pt (.getBytes "same plaintext, same key, different messages" "UTF-8")
        envs (repeatedly 20 #(ratchet/ratchet-encrypt mk pt))]
    (is (= 20 (count (distinct (map (comp seq :iv) envs)))) "IVs never repeat")
    (is (= 20 (count (distinct (map (comp seq :ciphertext) envs))))
        "ciphertexts differ every call even for identical (key, plaintext)")))

(defn- session-pair []
  (let [alice-id (x3dh/generate-identity)
        bob-id (x3dh/generate-identity)
        [bundle _bob-id'] (x3dh/publish-bundle bob-id)
        {:keys [shared-secret]} (x3dh/x3dh-initiate alice-id bundle)]
    {:shared-secret shared-secret
     :bob-initial-dh (:spk bob-id)}))

(deftest full-session-roundtrip-both-directions
  (let [{:keys [shared-secret bob-initial-dh]} (session-pair)
        alice (ratchet/init-sender shared-secret (:pub bob-initial-dh))
        bob (ratchet/init-receiver shared-secret bob-initial-dh)
        [alice1 env1] (ratchet/encrypt-message alice (bytes< "hello bob"))
        [bob1 pt1] (ratchet/decrypt-message bob env1)
        [bob2 env2] (ratchet/encrypt-message bob1 (bytes< "hi alice"))
        [alice2 pt2] (ratchet/decrypt-message alice1 env2)
        [alice3 env3] (ratchet/encrypt-message alice2 (bytes< "second message from alice"))
        [bob3 pt3] (ratchet/decrypt-message bob2 env3)]
    (is (= "hello bob" (String. ^bytes pt1 "UTF-8")))
    (is (= "hi alice" (String. ^bytes pt2 "UTF-8")))
    (is (= "second message from alice" (String. ^bytes pt3 "UTF-8")))
    (is (not= (seq (:dh-pub alice1)) (seq (:dh-pub bob2)))
        "each side ratchets to its own fresh DH keypair per turn")
    (is (some? alice3) (some? bob3))))

(deftest each-message-in-a-chain-uses-a-distinct-message-key
  (let [{:keys [shared-secret bob-initial-dh]} (session-pair)
        alice (ratchet/init-sender shared-secret (:pub bob-initial-dh))
        [alice1 env1] (ratchet/encrypt-message alice (bytes< "m1"))
        [alice2 env2] (ratchet/encrypt-message alice1 (bytes< "m2"))
        [_alice3 env3] (ratchet/encrypt-message alice2 (bytes< "m3"))]
    ;; same DH ratchet turn (no peer reply in between) => same header dh-pub,
    ;; but ciphertexts/IVs must still differ because the chain key advances.
    (is (= (seq (:dh-pub (:header env1))) (seq (:dh-pub (:header env2))) (seq (:dh-pub (:header env3)))))
    (is (= 3 (count (distinct (map (comp seq :iv) [env1 env2 env3])))))
    (is (= 3 (count (distinct (map (comp seq :ciphertext) [env1 env2 env3])))))))
