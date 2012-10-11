// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wots

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

var otssha256 = NewScheme(sha256.New)

func TestSignVerify(t *testing.T) {
	k, err := otssha256.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keys: %s", err)
	}
	msg := []byte(testMessage)
	sig := otssha256.Sign(k, msg)
	if !otssha256.Verify(k.PublicKey, msg, sig) {
		t.Fatalf("failed to verify correct signature")
	}

	if otssha256.Verify(k.PublicKey, msg[1:], sig) {
		t.Fatalf("verified wrong message")
	}

	sig[1] = 0
	if otssha256.Verify(k.PublicKey, msg, sig) {
		t.Fatalf("verified wrong signature")
	}

}

var testMessage = "hello world!"
var testPublicKey = "MgeQR6kMn7TrdNq3RvI8yW87mG+aPtHnN/BPcjxh+hI="
var testSig = "26nqg3vlDt5JofQw11P+rY1GO3p0XOyiIUB3tuGiT5k5C59N/G/OX+WUuPRi" +
	"asg36Sx77v+bLlGeB5Z46lDKP1AahD9cD3GhpYVfFMvqxiA3HEANRDkpSakN" +
	"YpTJKMuzXFQ7J9gmLS64kUm9dOudH080IP6/Gs4wscY1wX9yB6ncg/6xqVHL" +
	"xTBg3Br8+VknG2FecoFVLn/0arDvWw06lteOshb1JuStefAVJE4Iywb4ehcu" +
	"GJ4kSkFHzhQfINZd9PwFwenk1pVXqzo/F4W8nYIAjq/Jb7WwW4G05FHgcxDF" +
	"6tnyHkmsRaCHRgzFB9SFabLq7E4JsVEQFx2gMLxQncQ28+42N/bNvO8HNTCr" +
	"lWozvMEwJnCL+e2zLerxucsCfDGE7/OruRSCLcRuv+DFkq2im/2qd3LFSq2R" +
	"bsTGd5soXv476IFH2r9Xq4EXn6tXP7K9rPwn/LLnB1v28Yym2UkK4Xi8qAhG" +
	"r0KeRNhbd1xy/tlKExlE2z9RM0aFxo84wHFOuSUWLhqpsy56yltun9pRZm0o" +
	"q8UMbSN6ms2lYE8QFv97RKs4Jk2I1NbwgBLvbGBVAbXFZVjD5eMIBkkIDSCf" +
	"fFO8JPG8RXiRMg3bgzPy4ZAZfjgucvVJAL4QgliomxD7KAf3OLcUAwpMUV2D" +
	"BYL328xNMMlhXIPd2eTwYMjizrYEsnF1E8HmkNJbBUj5u7vl9SjGOUyxHiCg" +
	"HgU2pJgPNB0OPbl5Av/qttgWaXEYxtDEULbxdS91aYFk1z5E8HXbjV+SKPCN" +
	"/OPpywBPd1cxxXugz5PgQEZYzQO+wq3HjbhUf3ERlzeg0v4/FNPO0EEU7vx+" +
	"7mk0izf2On0rtucor9qwwjAWsG6H1YTyvXJAmv1pB4ZbZI9mISrZOwG4ar/e" +
	"QhP9vFK5itfjdqbqXCGt67DPRFGci9EfKarLbcuozKntvLWrEIMs3GO0Do1t" +
	"0c3P3O45IsQ7yLWOR4LfBoM5TIhncsnuycMnQU86BL6Kq7db7LLCkiYApZ9P" +
	"eQmTOi4r51finbPlbS/FGbDmxqTM8Pvx79Ld++5oVU3aX97NMEIDVDRDbVOv" +
	"UIiio4kgg0xSEcMc5jjdOukFGYUtToA8RVBwOGwnRk9xpp71HRkQbOmEH0bI" +
	"HLy6kPkRMv5Yq6zpRb7qrd7kTvUAIVCaKCtI+zkf8BERawcAKhnFa6wgkEXJ" +
	"Z/GM+AsAa4e6FLgHh0/qUYGX+bltv00dZEOwHcIliOhX8wURNT7W5eU1E3vs" +
	"+rj++xVvS3AXNS2xppTl39bSHWjjPKxT3PbO8ZDFNTN2AdNZWRXD50VDxRCM" +
	"PL45JKyr8PaBBbTdVt5zivzrVIWUyQl2L6Ps9ID/r3gveng4DYtlhh2I1LmE" +
	"dUFyFtf7CdnhGPdxp3hD//m2EH1qjgdVW4Sl2FUM5k908XgmfRZE6hfP2xb0" +
	"gFP+coYa8oLRibjibUHrz2OclqXesJhcHsR4zXtlz7Qq7xSfxJitGg=="

func TestVerify(t *testing.T) {
	pk, err := base64.StdEncoding.DecodeString(testPublicKey)
	if err != nil {
		t.Fatalf("decoding public key: %s", err)
	}
	sig, err := base64.StdEncoding.DecodeString(testSig)
	if err != nil {
		t.Fatalf("decoding signature: %s", err)
	}
	if !otssha256.Verify(pk, []byte(testMessage), sig) {
		t.Fatalf("failed to verify correct signature")
	}

}

type devZero int

func (z *devZero) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

var zeroReader = new(devZero)

func BenchmarkSignVerifySHA256(b *testing.B) {
	msg := []byte(testMessage)
	k, _ := otssha256.GenerateKey(zeroReader)
	klen := len(k.B)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig := otssha256.Sign(k, msg)
		otssha256.Verify(k.PublicKey, msg, sig)
		k.B = make([]byte, klen)
	}
}
