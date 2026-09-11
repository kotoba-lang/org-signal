;; kotoba.signal.hkdf — HKDF-SHA256 (RFC 5869), self-contained.
;;
;; The JVM has NO built-in HKDF (only the raw HMAC primitive it's built from), so
;; this implements RFC 5869 §2.2/§2.3 directly on top of `javax.crypto.Mac`
;; ("HmacSHA256") — no third-party crypto library. Correctness is pinned against
;; ALL THREE RFC 5869 A.1–A.3 test vectors in hkdf_test.clj (basic, longer
;; inputs/outputs, zero-length salt/info), byte-for-byte.
;;
;;   (require '[kotoba.signal.hkdf :as hkdf])
;;   (hkdf/hkdf-extract salt ikm)              ; -> bytes32 (PRK)
;;   (hkdf/hkdf-expand prk info length)        ; -> bytes[length] (OKM)
;;   (hkdf/hkdf salt ikm info length)          ; -> bytes[length] (extract-then-expand, one call)
(ns kotoba.signal.hkdf
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def ^:const hash-len 32) ; SHA-256 output size

(defn- hmac-sha256
  "Raw HMAC-SHA256(key, data). Per RFC 2104 / FIPS 198-1, a zero-length key is
   valid (HMAC pads it out to the block size internally), so callers may pass an
   all-zero 32-byte salt for the RFC 5869 'no salt provided' case."
  ^bytes [^bytes key ^bytes data]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. key "HmacSHA256"))
    (.doFinal mac data)))

(defn hkdf-extract
  "RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM). A nil/empty salt is replaced with
   HashLen zero bytes, per spec."
  ^bytes [^bytes salt ^bytes ikm]
  (let [salt (if (or (nil? salt) (zero? (alength ^bytes salt)))
               (byte-array hash-len)
               salt)]
    (hmac-sha256 salt ikm)))

(defn hkdf-expand
  "RFC 5869 §2.3: OKM = T(1) || T(2) || ... truncated to `length` bytes, where
   T(0) = \"\", T(i) = HMAC-Hash(PRK, T(i-1) || info || i). `length` must be
   <= 255 * HashLen (RFC 5869 constraint; SHA-256 => <= 8160 bytes)."
  ^bytes [^bytes prk info ^long length]
  (let [info (or info (byte-array 0))
        n (long (Math/ceil (/ (double length) hash-len)))]
    (when (> n 255)
      (throw (ex-info "hkdf-expand: requested length too large" {:length length})))
    (loop [i 1 prev (byte-array 0) acc (transient [])]
      (if (> i n)
        (byte-array (take length (mapcat identity (persistent! acc))))
        (let [t (hmac-sha256 prk (byte-array (concat (seq prev) (seq info) [(unchecked-byte i)])))]
          (recur (inc i) t (conj! acc (seq t))))))))

(defn hkdf
  "RFC 5869 §2.1: HKDF(salt, ikm, info, length) = expand(extract(salt, ikm), info, length)."
  ^bytes [salt ikm info length]
  (hkdf-expand (hkdf-extract salt ikm) info length))
