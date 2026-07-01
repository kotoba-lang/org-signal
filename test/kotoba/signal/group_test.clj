(ns kotoba.signal.group-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.signal.group :as group]))

(deftest distribution-message-verifies
  (let [sk (group/create-sender-key)
        dist (group/distribution-message sk 0)]
    (is (true? (group/verify-distribution dist)))))

(deftest forged-distribution-is-rejected
  (let [sk (group/create-sender-key)
        other (group/create-sender-key)
        dist (group/distribution-message sk 0)
        forged (assoc dist :chain-key (:chain-key other))] ; swap in a different chain-key, keep old sig
    (is (false? (group/verify-distribution forged)))))

(deftest sender-and-member-derive-identical-message-keys-in-lockstep
  (let [sk (group/create-sender-key)
        dist (group/distribution-message sk 0)
        [sk1 sender-mk1] (group/sender-advance sk)
        [sk2 sender-mk2] (group/sender-advance sk1)
        [sk3 _sender-mk3] (group/sender-advance sk2)
        [ck1 member-mk1] (group/member-derive (:chain-key dist))
        [ck2 member-mk2] (group/member-derive ck1)]
    (is (= (seq sender-mk1) (seq member-mk1)) "step 1 message keys agree")
    (is (= (seq sender-mk2) (seq member-mk2)) "step 2 message keys agree")
    (is (some? sk3))))

(deftest segment-encrypt-decrypt-roundtrip
  (let [sk (group/create-sender-key)
        dist (group/distribution-message sk 0)
        [_sk1 sender-mk] (group/sender-advance sk)
        [_ck1 member-mk] (group/member-derive (:chain-key dist))
        segment (.getBytes "aozora private segment #42" "UTF-8")
        env (group/encrypt-segment sender-mk segment)]
    (is (= (seq segment) (seq (group/decrypt-segment member-mk env))))))

(deftest chain-forward-secrecy-distinct-keys-per-segment
  (let [sk (group/create-sender-key)
        n 50
        keys (loop [sk sk i 0 acc []]
               (if (= i n)
                 acc
                 (let [[sk' mk] (group/sender-advance sk)]
                   (recur sk' (inc i) (conj acc (seq mk))))))]
    (is (= n (count (distinct keys))) "no two segment keys collide across 50 chain steps")))

(deftest members-cannot-derive-without-a-valid-distribution
  (let [sk (group/create-sender-key)
        bogus-chain-key (byte-array 32)]
    ;; a member that never got a real distribution has no way to reach the
    ;; sender's actual chain position; its derived keys diverge immediately.
    (let [[_sk1 real-mk] (group/sender-advance sk)
          [_ck bogus-mk] (group/member-derive bogus-chain-key)]
      (is (not= (seq real-mk) (seq bogus-mk))))))
