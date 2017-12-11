// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wots implements Winternitz-Lamport-Diffie one-time signature scheme.
//
// If the hash function is one-way and of sufficient length, the private key is
// random, not known to the attacker, and used to sign only one message, and
// there are no bugs in this implementation, it is infeasible to forge
// signatures (even on quantum computer, provided that it can't break the
// underlying hash function).
//
// Implementation details
//
// Cost/size trade-off parameter w=8 bits, which means that public key
// generation takes (n+2)*256+1 hash function evaluations, where n is hash
// output size in bytes. Similarly, on average, signing or verifying a single
// message take 1+((n+2)*255)/2 evaluations.
//
// Message hash is calculated with randomization as specified in NIST
// SP-800-106 "Randomized Hashing for Digital Signatures", with length
// of randomization string equal to the length of hash function output.
// The randomization string is prepended to the signature.
package wots

import (
	"bytes"
	"errors"
	"hash"
	"io"
)

// TODO(dchest): find a better name for Scheme.

// Scheme represents one-time signature signing/verification configuration.
type Scheme struct {
	blockSize int
	hashFunc  func() hash.Hash
	rand io.Reader
}

// NewScheme returns a new signing/verification scheme from the given function
// returning hash.Hash type. The hash function output size must have minimum 16
// and maximum 128 bytes, otherwise GenerateKey method of this scheme will always
// return error.
func NewScheme(h func() hash.Hash, rand io.Reader) *Scheme {
	return &Scheme{
		blockSize: h().Size(),
		hashFunc:  h,
		rand: rand,
	}
}

// PublicKeySize returns public key size in bytes.
func (s *Scheme) PublicKeySize() int { return s.blockSize }

// SignatureSize returns signature size in bytes.
func (s *Scheme) SignatureSize() int { return (s.blockSize+2)*s.blockSize + s.blockSize }

type PrivateKey struct {
	PublicKey []byte // public key bytes
	B         []byte // private key bytes
}

// hashBlock returns in hashed the given number of times: H(...H(in)).
// If times is 0, returns a copy of input without hashing it.
func hashBlock(h hash.Hash, in []byte, times int) (out []byte) {
	out = append(out, in...)
	for i := 0; i < times; i++ {
		h.Reset()
		h.Write(out)
		out = h.Sum(out[:0])
	}
	return
}

// GenerateKey generates a new private and public key pair.
func (s *Scheme) GenerateKey() (*PrivateKey, error) {
	if s.blockSize < 16 || s.blockSize > 128 {
		return nil, errors.New("wrong hash output size")
	}
	// Generate random private key.
	randKeySl := make([]byte, (s.blockSize+2)*s.blockSize)
	if _, err := io.ReadFull(s.rand, randKeySl); err != nil {
		return nil, err
	}

	return s.BytesToPrivateKey(randKeySl)
}

//bytes to *PrivateKey object
func (s *Scheme) BytesToPrivateKey (srcKey []byte) (*PrivateKey, error){
	// Create public key from private key.
	keyHash := s.hashFunc()
	blockHash := s.hashFunc()
	for i := 0; i < len(srcKey); i += s.blockSize {
		keyHash.Write(hashBlock(blockHash, srcKey[i:i+s.blockSize], 256))
	}
	return &PrivateKey{keyHash.Sum(nil), srcKey}, nil
}

// messageDigest returns a randomized digest of message with 2-byte checksum.
func messageDigest(h hash.Hash, r []byte, msg []byte) []byte {
	// Randomized hashing (NIST SP-800-106).
	//
	//  Padding: m = msg ‖ 0x80 [0x00...]
	//  Hashing: H(r ‖ m1 ⊕ r, ..., mL ⊕ r ‖ rv_length_indicator)
	//    where m1..mL are blocks of size len(r) of padded msg,
	//    and rv_length_indicator is 16-byte big endian len(r).
	//
	h.Write(r)
	rlen := len(r)
	tmp := make([]byte, rlen)
	for len(msg) >= rlen {
		for i, m := range msg[:rlen] {
			tmp[i] = m ^ r[i]
		}
		h.Write(tmp)
		msg = msg[rlen:]
	}
	for i := range tmp {
		tmp[i] = 0
	}
	copy(tmp, msg)
	tmp[len(msg)] = 0x80
	for i := range tmp {
		tmp[i] ^= r[i]
	}
	h.Write(tmp)
	tmp[0] = uint8(rlen >> 8)
	tmp[1] = uint8(rlen)
	h.Write(tmp[:2])
	d := h.Sum(nil)

	// Append checksum of digest bits.
	var sum uint16
	for _, v := range d {
		sum += 256 - uint16(v)
	}
	return append(d, uint8(sum>>8), uint8(sum))
}

// Sign signs an arbitrary length message using the given private key and
// returns signature. After signing, private key bytes are destroyed and the
// same key cannot be used again to sign more messages.
func (s *Scheme) Sign(k *PrivateKey, message []byte) (sig []byte) {
	// Generate message randomization parameter.
	// Note that r must be different for each generated message, but since
	// we already can't use the same private key to sign more than one
	// message, we can generate it here rather than when signing.
	randomParamSl := make([]byte, s.blockSize)
	if _, err := io.ReadFull(s.rand, randomParamSl); err != nil {
		return nil
	}
	sig = append(sig, randomParamSl...)
	blockHash := s.hashFunc()
	//TODO. why copy ? k.B[:s.blockSize]
	b := k.B
	for _, v := range messageDigest(s.hashFunc(), randomParamSl, message) {
		sig = append(sig, hashBlock(blockHash, b[:s.blockSize], int(v))...)
		b = b[s.blockSize:]
	}
	// Destroy private key bytes.
	for i := range k.B {
		k.B[i] = 0
	}
	k.B = nil
	return
}

// Verify verifies the signature of message using the public key,
// and returns true iff the signature is valid.
// 
// Note: verification time depends on message and signature.
func (s *Scheme) Verify(publicKey []byte, message []byte, sig []byte) bool {
	if len(publicKey) != s.PublicKeySize() || len(sig) != s.SignatureSize() {
		return false
	}
	d := messageDigest(s.hashFunc(), sig[:s.blockSize], message)
	sig = sig[s.blockSize:]
	keyHash := s.hashFunc()
	blockHash := s.hashFunc()
	for _, v := range d {
		keyHash.Write(hashBlock(blockHash, sig[:s.blockSize], 256-int(v)))
		sig = sig[s.blockSize:]
	}
	return bytes.Equal(keyHash.Sum(nil), publicKey)
}
