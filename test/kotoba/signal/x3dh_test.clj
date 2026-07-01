(ns kotoba.signal.x3dh-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.signal.x3dh :as x3dh]))

(deftest bundle-signature-verifies
  (let [bob (x3dh/generate-identity)
        [bundle _bob'] (x3dh/publish-bundle bob)]
    (is (true? (x3dh/verify-bundle bundle)))))

(deftest tampered-bundle-signature-is-rejected
  (let [bob (x3dh/generate-identity)
        [bundle _] (x3dh/publish-bundle bob)
        other (x3dh/generate-identity)
        forged (assoc bundle :spk (:pub (:spk other)))] ; swap in an unsigned spk
    (is (false? (x3dh/verify-bundle forged)))))

(deftest x3dh-roundtrip-with-opk
  (dotimes [_ 5]
    (let [alice (x3dh/generate-identity)
          bob (x3dh/generate-identity)
          [bundle _bob'] (x3dh/publish-bundle bob)
          _ (is (true? (x3dh/verify-bundle bundle)))
          {:keys [shared-secret ek-pub opk-id]} (x3dh/x3dh-initiate alice bundle)
          bob-sk (x3dh/x3dh-respond bob (:pub (:ik alice)) ek-pub opk-id)]
      (is (some? opk-id) "bob published an opk, so alice should have consumed one")
      (is (= 32 (alength shared-secret)))
      (is (= (seq shared-secret) (seq bob-sk))
          "alice's x3dh-initiate and bob's x3dh-respond must derive the identical secret"))))

(deftest x3dh-roundtrip-without-opk
  (let [alice (x3dh/generate-identity)
        bob (x3dh/generate-identity 0) ; no one-time prekeys
        [bundle _] (x3dh/publish-bundle bob)
        {:keys [shared-secret ek-pub opk-id]} (x3dh/x3dh-initiate alice bundle)
        bob-sk (x3dh/x3dh-respond bob (:pub (:ik alice)) ek-pub opk-id)]
    (is (nil? opk-id))
    (is (nil? (:opk bundle)))
    (is (= (seq shared-secret) (seq bob-sk)))))

(deftest different-sessions-produce-different-secrets
  (let [alice (x3dh/generate-identity)
        bob (x3dh/generate-identity)
        [bundle bob'] (x3dh/publish-bundle bob)
        s1 (:shared-secret (x3dh/x3dh-initiate alice bundle))
        [bundle2 _] (x3dh/publish-bundle bob')
        s2 (:shared-secret (x3dh/x3dh-initiate alice bundle2))]
    (is (not= (seq s1) (seq s2))
        "fresh ephemeral key + fresh opk per session => independent secrets")))

(deftest opk-pool-is-consumed-one-at-a-time
  (testing "publish-bundle pops exactly one opk and doesn't repeat it"
    (let [bob (x3dh/generate-identity 3)
          [b1 bob1] (x3dh/publish-bundle bob)
          [b2 bob2] (x3dh/publish-bundle bob1)
          [b3 bob3] (x3dh/publish-bundle bob2)]
      (is (= [0 1 2] [(:opk-id b1) (:opk-id b2) (:opk-id b3)]))
      (is (empty? (:opks bob3))))))
