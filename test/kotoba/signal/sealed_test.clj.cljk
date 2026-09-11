(ns kotoba.signal.sealed-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.protocol.sealed :as proto]
            [kotoba.signal.ratchet :as ratchet]
            [kotoba.signal.sealed :as sealed]
            [kotoba.signal.x3dh :as x3dh])
  (:import (java.security MessageDigest)
           (javax.crypto AEADBadTagException)))

(def ipns (str "k51qzi5uqu5d" (apply str (repeat 50 "a"))))
(def file-cid "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq")

(defn- shape-cid
  "Injected hasher: shape-valid CID, not a real multihash. Protocol does
   not hash; tests must not pretend this ns grew a hasher."
  [x]
  (let [md (.digest (MessageDigest/getInstance "SHA-256")
                    (.getBytes (pr-str x) "UTF-8"))
        alphabet "abcdefghijklmnopqrstuvwxyz234567"
        chars (map #(nth alphabet (bit-and (int %) 31)) md)]
    (str "bafkrei" (apply str chars))))

(defn- alice-roles [alice]
  {:ipns "k-ipns" :peer "k-peer" :signal (str "sig-" (alength ^bytes (:pub (:ik alice))))})

(deftest published-bundle-is-public-and-pq-absent
  (let [bob (x3dh/generate-identity)
        {:keys [public remaining]} (sealed/publish bob)]
    (is (true? (proto/bundle? public)))
    (is (false? (:confidential? public)))
    (is (nil? (:pq-prekey public))
        "missing PQ prekey is absence, not a silent hybrid upgrade")
    (is (= (dec (count (:opks bob))) (count (:opks remaining))))
    (is (false? (proto/opk-once-on-content-addressed?)))))

(deftest colliding-key-roles-are-refused
  (let [bob (x3dh/generate-identity)]
    (is (= :key-role-collision
           (:error (sealed/publish bob {:ipns "same" :peer "same" :signal "other"}))))
    (is (= :key-role-collision
           (:error (sealed/initiate (x3dh/generate-identity)
                                    (:public (sealed/publish bob))
                                    {:ipns "a" :peer "b" :signal "a"}))))))

(deftest file-key-travels-inside-ratchet-plaintext
  (let [bob (x3dh/generate-identity)
        alice (x3dh/generate-identity)
        {:keys [public]} (sealed/publish bob)
        alice-s (sealed/initiate alice public (alice-roles alice))
        body {:text "hello bob"
              :attachments [{:cid file-cid
                             :file-key "the-real-file-key"
                             :size 12
                             :digest "abc"}]}
        [alice1 msg] (sealed/encrypt alice-s body)
        stored (sealed/store-msg msg shape-cid)
        [bob-s opened] (sealed/accept bob msg)]
    (is (true? (:ok? alice-s)))
    (is (true? (proto/message? msg)))
    (is (= :session (:construction msg)))
    (is (= sealed/in-session-wrap (get-in msg [:attachments 0 :wrapped-key])))
    (is (nil? (get-in msg [:attachments 0 :file-key]))
        "outer attachment must not carry the file key")
    (is (not (re-find #"the-real-file-key" (pr-str msg)))
        "mailbox-readable object must not contain the file key")
    (is (= :object (:construction stored)))
    (is (= :session-ciphertext (:body-is stored)))
    (is (some? alice1))
    (is (= "hello bob" (:text opened)))
    (is (= "the-real-file-key" (get-in opened [:attachments 0 :file-key]))
        "file key is recovered only after Double Ratchet decrypt")
    (is (= file-cid (get-in opened [:attachments 0 :cid])))
    (is (some? bob-s))))

(deftest full-session-then-mailbox-then-reply
  (let [bob (x3dh/generate-identity)
        alice (x3dh/generate-identity)
        {:keys [public]} (sealed/publish bob)
        alice0 (sealed/initiate alice public)
        [alice1 msg1] (sealed/encrypt alice0 {:text "m1"})
        [bob1 opened1] (sealed/accept bob msg1)
        [_bob2 msg2] (sealed/encrypt bob1 {:text "m2"})
        [alice2 opened2] (sealed/decrypt alice1 msg2)
        stored1 (sealed/store-msg msg1 shape-cid)
        stored2 (sealed/store-msg msg2 shape-cid)
        mb0 (proto/mailbox)
        mb1 (sealed/put-in-mailbox mb0 stored1 shape-cid)
        mb2 (sealed/put-in-mailbox mb1 stored2 shape-cid)
        head (sealed/publish-head ipns (:head mb2))]
    (is (= "m1" (:text opened1)))
    (is (= "m2" (:text opened2)))
    (is (true? (proto/entries-prefix? mb1 mb2)))
    (is (= 2 (count (:entries mb2))))
    (is (not= (:cid stored1) (:cid stored2)))
    (is (false? (:confidential? head))
        "IPNS authenticates a pointer; it does not hide the mailbox")
    (is (false? (:mutates-name? head)))
    (is (= :naming (:plane head)))
    (is (some? alice2))))

(deftest identical-plaintext-does-not-imply-identical-cid
  (testing "ratchet IVs / chain keys advance — convergent encryption is forbidden"
    (let [bob (x3dh/generate-identity)
          alice (x3dh/generate-identity)
          {:keys [public]} (sealed/publish bob)
          alice0 (sealed/initiate alice public)
          [_ msg-a] (sealed/encrypt alice0 {:text "same"})
          alice0' (sealed/initiate alice public)
          [_ msg-b] (sealed/encrypt alice0' {:text "same"})]
      (is (not= (:ciphertext msg-a) (:ciphertext msg-b)))
      (is (not= (shape-cid msg-a) (shape-cid msg-b)))
      (is (false? (proto/convergent-allowed?))))))

(deftest plaintext-on-attachment-is-rejected
  (let [bob (x3dh/generate-identity)
        alice (x3dh/generate-identity)
        alice-s (sealed/initiate alice (:public (sealed/publish bob)))
        [_ msg] (sealed/encrypt alice-s {:text "x"
                                         :attachments [{:cid file-cid
                                                        :file-key "k"
                                                        :plaintext "no"}]})]
    (is (= :plaintext-in-attachment (:error msg)))))

(deftest receiver-cannot-send-before-first-decrypt
  (let [bob (x3dh/generate-identity)
        premature {:ok? true
                   :role :responder
                   :ratchet (ratchet/init-receiver (byte-array 32) (:spk bob))}
        [_ err] (sealed/encrypt premature {:text "too soon"})]
    (is (= :cannot-send-before-receive (:error err)))))

(deftest tampered-header-n-is-rejected
  (let [bob (x3dh/generate-identity)
        alice (x3dh/generate-identity)
        alice-s (sealed/initiate alice (:public (sealed/publish bob)))
        [_ msg] (sealed/encrypt alice-s {:text "hello"})
        tampered (update-in msg [:header :n] inc)]
    (is (thrown? AEADBadTagException (sealed/accept bob tampered)))))

(deftest hop-is-not-this-construction
  (is (false? (proto/hop-is-e2ee?)))
  (is (false? (proto/dag-jose-is-ratchet?)))
  (is (true? (proto/e2ee-is-not-session-plane?))))
