(ns kotoba.signal.hkdf-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.signal.hkdf :as hkdf])
  (:import (java.util HexFormat)))

(defn- unhex ^bytes [^String s] (.parseHex (HexFormat/of) s))
(defn- hex ^String [^bytes b] (.formatHex (HexFormat/of) b))

;; RFC 5869 Appendix A — HKDF-SHA256 test vectors (A.1, A.2, A.3), verbatim.

(deftest rfc5869-test-case-1-basic
  (let [ikm  (unhex (apply str (repeat 22 "0b")))
        salt (unhex "000102030405060708090a0b0c")
        info (unhex "f0f1f2f3f4f5f6f7f8f9")
        prk  (hkdf/hkdf-extract salt ikm)
        okm  (hkdf/hkdf-expand prk info 42)]
    (is (= "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" (hex prk)))
    (is (= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
           (hex okm)))
    (is (= (seq okm) (seq (hkdf/hkdf salt ikm info 42))))))

(deftest rfc5869-test-case-2-longer-inputs
  (let [ikm  (unhex (apply str (map #(format "%02x" %) (range 0 80))))
        salt (unhex (apply str (map #(format "%02x" %) (range 0x60 (+ 0x60 80)))))
        info (unhex (apply str (map #(format "%02x" %) (range 0xb0 (+ 0xb0 80)))))
        prk  (hkdf/hkdf-extract salt ikm)
        okm  (hkdf/hkdf-expand prk info 82)]
    (is (= "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244" (hex prk)))
    (is (= (str "b11e398dc80327a1c8e7f78c596a4934"
                "4f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f1d87")
           (hex okm)))))

(deftest rfc5869-test-case-3-zero-length-salt-and-info
  (let [ikm  (unhex (apply str (repeat 22 "0b")))
        salt (byte-array 0)
        info (byte-array 0)
        prk  (hkdf/hkdf-extract salt ikm)
        okm  (hkdf/hkdf-expand prk info 42)]
    (is (= "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" (hex prk)))
    (is (= "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
           (hex okm)))
    (is (= (seq okm) (seq (hkdf/hkdf nil ikm nil 42))) "nil salt/info == zero-length salt/info")))

(deftest hkdf-expand-rejects-oversized-length
  (is (thrown? clojure.lang.ExceptionInfo
               (hkdf/hkdf-expand (byte-array 32) (byte-array 0) (* 256 32)))))
